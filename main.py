# __________                  __             __     ________             .___ 
# \______   \  ____    ____  |  | __  ____ _/  |_  /  _____/   ____    __| _/ 
#  |       _/ /  _ \ _/ ___\ |  |/ /_/ __ \\   __\/   \  ___  /  _ \  / __ |  
#  |    |   \(  <_> )\  \___ |    < \  ___/ |  |  \    \_\  \(  <_> )/ /_/ |  
#  |____|_  / \____/  \___  >|__|_ \ \___  >|__|   \______  / \____/ \____ |  
#         \/              \/      \/     \/               \/              \/  
#
# Shodan Discord Bot by RocketGod
#
# https://github.com/RocketGod-git/shodanbot

import json
import logging

from ipaddress import ip_address
import base64
import io
import re

import discord
from discord import Embed
import discord.errors
from discord import ui

import shodan


# Reset logging configuration to clear any handlers
logging.root.handlers = []

# Define the logger and handler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create console handler with a specific level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# Create formatter and add it to the handler
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] - %(message)s')
ch.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(ch)

# Mute the discord library's logs
logging.getLogger('discord').setLevel(logging.CRITICAL)

# Specifically mute INFO level logs from discord.gateway
logging.getLogger('discord.gateway').setLevel(logging.ERROR)

def load_config():
    try:
        with open('config.json', 'r') as file:
            return json.load(file)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None

def check_configurations(config):
    if not config:
        return False

    required_keys = ['TOKEN', 'SHODAN_KEY']
    missing_keys = [key for key in required_keys if key not in config]

    if missing_keys:
        logger.error(f"Missing keys in config.json: {', '.join(missing_keys)}")
        return False

    return True

def is_ipv6(addr: str) -> bool:
    """Checks if the given address is an IPv6 address."""
    try:
        return ip_address(addr).version == 6
    except ValueError:
        return False

class aclient(discord.Client):
    def __init__(self, shodan_key) -> None:
        super().__init__(intents=discord.Intents.default())
        self.shodan = shodan.Shodan(shodan_key)
        self.tree = discord.app_commands.CommandTree(self)
        self.activity = discord.Activity(type=discord.ActivityType.watching, name="/shodan")
        self.discord_message_limit = 2000

    async def send_split_messages(self, interaction, message: str, require_response=True):
        """Sends a message, and if it's too long for Discord, splits it."""
        # Handle empty messages
        if not message.strip():
            logging.warning("Attempted to send an empty message.")
            return

        # Extract the user's query/command from the interaction to prepend it to the first chunk
        query = ""
        for option in interaction.data.get("options", []):
            if option.get("name") == "query":
                query = option.get("value", "")
                break

        prepend_text = ""
        if query:
            prepend_text = f"Query: {query}\n\n"

        lines = message.split("\n")
        chunks = []
        current_chunk = ""

        # First, add the prepend_text (if any) to the initial chunk
        if prepend_text:
            current_chunk += prepend_text

        for line in lines:
            # If the individual line is too long, split it up before chunking
            while len(line) > self.discord_message_limit:
                sub_line = line[:self.discord_message_limit]
                if len(current_chunk) + len(sub_line) + 1 > self.discord_message_limit:
                    chunks.append(current_chunk)
                    current_chunk = ""
                current_chunk += sub_line + "\n"
                line = line[self.discord_message_limit:]

            # If adding the next line to the current chunk would exceed the Discord message limit
            if len(current_chunk) + len(line) + 1 > self.discord_message_limit:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"

        if current_chunk:
            chunks.append(current_chunk)

        # Check if there are chunks to send
        if not chunks:
            logging.warning("No chunks generated from the message.")
            return

        # If a response is required and the interaction hasn't been responded to, defer the response
        if require_response and not interaction.response.is_done():
            await interaction.response.defer(ephemeral=False)

        # Edit the deferred response
        try:
            await interaction.followup.send(content=chunks[0], ephemeral=False)
            chunks = chunks[1:]  # Remove the first chunk since we've already sent it
        except Exception as e:
            logging.error(f"Failed to send the first chunk via followup. Error: {e}")

        # Send the rest of the chunks directly to the channel
        for chunk in chunks:
            try:
                await interaction.channel.send(chunk)
            except Exception as e:
                logging.error(f"Failed to send a message chunk to the channel. Error: {e}")

client = None

async def handle_errors(interaction, error, error_type="Error"):
    error_message = f"{error_type}: {error}"
    logger.error(f"Error occurred for user {interaction.user} in {interaction.guild.name if interaction.guild else 'Direct Message'}: {error_message}")

    try:
        # Check if the interaction has been responded to
        if interaction.response.is_done():
            await interaction.followup.send(error_message)
        else:
            await interaction.response.send_message(error_message, ephemeral=True)
    except discord.HTTPException as http_err:
        logger.warning(f"HTTP error while responding to {interaction.user}: {http_err}")
        try:
            await interaction.followup.send(error_message)
        except discord.HTTPException as followup_http_err:
            logger.error(f"HTTP error during followup to {interaction.user}: {followup_http_err}")
        except Exception as unexpected_followup_error:
            logger.error(f"Unexpected error during followup to {interaction.user}: {unexpected_followup_error}")
    except Exception as unexpected_err:
        logger.error(f"Unexpected error while responding to {interaction.user}: {unexpected_err}")
        try:
            await interaction.followup.send("An unexpected error occurred. Please try again later.")
        except Exception as followup_error:
            logger.error(f"Failed to send followup: {followup_error}")

async def process_shodan_results(interaction: discord.Interaction, result: dict, max_results: int = 10, display_mode: str = "full"):
    user = interaction.user.name
    guild_name = interaction.guild.name if interaction.guild else "Direct Message"
    command_name = interaction.data.get("name", "unknown_command")
    options = ", ".join([f"{option.get('name')}: {option.get('value')}" for option in interaction.data.get("options", [])])

    logger.info(f"{user} executed /{command_name} from {guild_name}. Options used: {options}")

    print(f"{user} executed /{command_name} from {guild_name}. Options used: {options}")

    matches = result.get('matches', [])
    if matches:
        total = result.get('total', 0)
        info = f"Found {total} results. Here are the top results:\n\n"

        # For list mode, send each IP link and screenshot immediately
        if display_mode == "easy":
            for match in matches[:max_results]:
                ip = match.get('ip_str', 'No IP available.')
                port = match.get('port', 'No port available.')

                # Format IP link
                clickable_link = f"[{ip}:{port}](http://{ip}:{port})\n"
                await interaction.followup.send(clickable_link, ephemeral=True)

                # Handle screenshot if available
                screenshot_data = match.get('screenshot', {}).get('data')
                if screenshot_data:
                    screenshot_bytes = base64.b64decode(screenshot_data)
                    screenshot_file = io.BytesIO(screenshot_bytes)
                    await interaction.followup.send(file=discord.File(screenshot_file, filename=f'screenshot_{ip}.jpg'))
            return 
        
        # If display mode is full
        responses = []  # Initialize the responses list
        for match in matches[:max_results]:
            detailed_info = generate_detailed_info(match)
            responses.append(detailed_info)
        
        message = info + "\n".join(responses)
        await client.send_split_messages(interaction, message)
    else:
        # Extract the user's query from the interaction
        query = ""
        for option in interaction.data.get("options", []):
            if option.get("name") == "query":
                query = option.get("value", "")
                break

        # If the query is not empty, include it in the response message
        response_message = "No results found."
        if query:
            response_message = f"No results found for the query: `{query}`."

        await interaction.followup.send(response_message)
        
def generate_detailed_info(match: dict) -> str:
    ip = match.get('ip_str', 'No IP available.')
    port = match.get('port', 'No port available.')
    org = match.get('org', 'N/A')
    product = match.get('product', 'N/A')
    version = match.get('version', 'N/A')
    data = match.get('data', 'No data available.').strip()
    asn = match.get('asn', 'N/A')
    hostnames = ", ".join(match.get('hostnames', [])) or 'N/A'
    os = match.get('os', 'N/A')
    timestamp = match.get('timestamp', 'N/A')
    isp = match.get('isp', 'N/A')
    http_title = match.get('http', {}).get('title', 'N/A')
    ssl_data = match.get('ssl', {}).get('cert', {}).get('subject', {}).get('CN', 'N/A')
    vulns = ", ".join(match.get('vulns', [])) or 'N/A'
    tags = ", ".join(match.get('tags', [])) or 'N/A'
    transport = match.get('transport', 'N/A')

    # Location details with Google Maps link
    lat = match.get('location', {}).get('latitude')
    long = match.get('location', {}).get('longitude')
    google_maps_link = f"https://www.google.com/maps?q={lat},{long}" if lat and long else None
    country = match.get('location', {}).get('country_name', 'N/A')
    city = match.get('location', {}).get('city', 'N/A')
    if google_maps_link:
        location = f"{country} - {city} ([Lat: {lat}, Long: {long}]({google_maps_link}))"
    else:
        location = f"{country} - {city} (Lat: {lat}, Long: {long})"

    main_link = f"http://{ip}:{port}"

    detailed_info = (
        f"**IP:** [{ip}]({main_link})\n"
        f"**Port:** {port}\n"
        f"**Transport:** {transport}\n"
        f"**Organization:** {org}\n"
        f"**Location:** {location}\n"
        f"**Product:** {product} {version}\n"
        f"**ASN:** {asn}\n"
        f"**Hostnames:** {hostnames}\n"
        f"**OS:** {os}\n"
        f"**ISP:** {isp}\n"
        f"**HTTP Title:** {http_title}\n"
        f"**SSL Common Name:** {ssl_data}\n"
        f"**Tags:** {tags}\n"
        f"**Vulnerabilities:** {vulns}\n"
        f"**Timestamp:** {timestamp}\n"
        f"**Data:** {data}\n"
        f"---"
    )

    return detailed_info


class QueryModal(discord.ui.Modal):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_item(discord.ui.TextInput(label="Enter your search query", style=discord.TextStyle.short, custom_id="query_input"))

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        query = self.children[0].value  # Extract the query from the modal
        view = MaxResultsView(query)
        message = await interaction.followup.send(content="Choose the maximum number of results:", view=view, ephemeral=False)
        view.query_message_id = message.id 
      
class MaxResultsView(discord.ui.View):
    def __init__(self, query):
        super().__init__()
        self.query = query
        self.message_id = None  # Used for the MaxResultsView message
        self.query_message_id = None 

    async def handle_search(self, interaction: discord.Interaction, max_results: int):
        shodan_client = interaction.client.shodan
        user = interaction.user.name
        guild_name = interaction.guild.name if interaction.guild else "Direct Message"

        logger.info(f"{user} initiated a search with query '{self.query}' in {guild_name}")

        try:
            result = shodan_client.search(self.query)
            matches = result.get('matches', [])

            if matches:
                limited_matches = matches[:max_results]
                total = result.get('total', 0)
                info = f"{user} used /shodan to search for `{self.query}` from {guild_name} and found {total} results. Here are the top {max_results} results:\n\n"

                if self.query_message_id:
                    try:
                        message_channel = interaction.channel
                        query_message = await message_channel.fetch_message(self.query_message_id)
                        await query_message.edit(content=info, view=None)  # Edit the message to display results
                        # logger.info(f"Successfully edited QueryModal message with ID: {self.query_message_id} to display results.")
                    except Exception as e:
                        logger.error(f"Error editing QueryModal message with ID {self.query_message_id}: {e}")

                await interaction.followup.send(info)

                for match in limited_matches:
                    ip = match.get('ip_str', 'No IP available.')
                    port = match.get('port', 'No port available.')

                    # Extract geolocation details for easy mode
                    lat = match.get('location', {}).get('latitude')
                    long = match.get('location', {}).get('longitude')
                    google_maps_link = f"https://www.google.com/maps?q={lat},{long}" if lat and long else None
                    geolocation_text = f"([map](<{google_maps_link}>))" if google_maps_link else ""

                    # Check if IP is IPv6
                    if is_ipv6(ip):
                        clickable_link = f"{ip} (port: {port}) {geolocation_text}"
                    else:
                        clickable_link = f"[{ip}:{port}](http://{ip}:{port}) {geolocation_text}"
                    
                    await interaction.channel.send(clickable_link)

                    screenshot_data = match.get('screenshot', {}).get('data')
                    if screenshot_data:
                        try:
                            screenshot_bytes = base64.b64decode(screenshot_data)
                            screenshot_file = io.BytesIO(screenshot_bytes)
                            screenshot_filename = f"screenshot_{match.get('ip_str', 'unknown')}.jpg"
                            screenshot_attachment = discord.File(screenshot_file, filename=screenshot_filename)
                            await interaction.channel.send("**Screenshot:**", file=screenshot_attachment)
                        except Exception as e:
                            logger.error(f"Error decoding screenshot data for IP {ip}: {e}")
                            await interaction.channel.send("**Screenshot:** Error decoding screenshot data.")
                
                # Send the entire API response as query.txt
                query_response = json.dumps(result, indent=2)
                query_file = discord.File(io.StringIO(query_response), filename="query.txt")
                await interaction.channel.send(file=query_file)
            else:
                await interaction.followup.send(content=f"No results found for the query: `{self.query}`.", ephemeral=True)
        
        except shodan.APIError as e:
            logger.error(f"Shodan API Error for user {user} in {guild_name}: {e}")
            await interaction.followup.send(content=f"Shodan API Error: {e}", ephemeral=True)
        except json.JSONDecodeError as e:
            logger.error(f"Unable to parse JSON response for user {user} in {guild_name}. Error: {e}")
            logger.error(f"Response content: {e.doc}")
            await interaction.followup.send(content=f"Unable to parse JSON response. Error: {e}", ephemeral=True)
        except discord.errors.DiscordServerError as e:
            logger.error(f"Discord server error occurred for user {user} in {guild_name}: {e}")
            await interaction.followup.send(content="A Discord server error occurred. Please try again later.", ephemeral=True)
        except Exception as e:
            logger.error(f"Unexpected error occurred for user {user} in {guild_name}: {e}")
            await interaction.followup.send(content=f"An unexpected error occurred: {e}", ephemeral=True)
        

    async def button_callback(self, interaction: discord.Interaction, max_results: int):
        if not interaction.response.is_done():
            await interaction.response.defer()

        # Disable the buttons in the view
        for child in self.children:
            child.disabled = True

        # Immediately edit the original QueryModal message to remove the content or view
        if self.query_message_id:
            try:
                message_channel = interaction.channel
                query_message = await message_channel.fetch_message(self.query_message_id)
                await query_message.edit(content="Processing your request...", view=None)
                # logger.info(f"Successfully edited QueryModal message with ID: {self.query_message_id} to indicate processing.")
            except discord.NotFound:
                logger.error(f"QueryModal message with ID {self.query_message_id} not found. It might have been deleted.")
            except discord.Forbidden:
                logger.error(f"Bot does not have permissions to edit QueryModal message with ID {self.query_message_id}.")
            except discord.HTTPException as e:
                logger.error(f"Failed to edit QueryModal message due to HTTPException: {e}")
            except Exception as e:
                logger.error(f"Unexpected error occurred when trying to edit QueryModal message with ID {self.query_message_id}: {e}")

        await self.handle_search(interaction, max_results)


    @discord.ui.button(label="20", style=discord.ButtonStyle.primary, custom_id="max_results_20")
    async def twenty_results_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.button_callback(interaction, 20)

    @discord.ui.button(label="50", style=discord.ButtonStyle.primary, custom_id="max_results_50")
    async def fifty_results_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.button_callback(interaction, 50)

    @discord.ui.button(label="100", style=discord.ButtonStyle.primary, custom_id="max_results_100")
    async def hundred_results_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.button_callback(interaction, 100)

    @discord.ui.button(label="250", style=discord.ButtonStyle.primary, custom_id="max_results_250")
    async def two_hundred_fifty_results_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.button_callback(interaction, 250)


def setup_bot_commands():
    @client.event
    async def on_ready():
        # Print the bot's connection status and list the servers it's connected to
        print(f'{client.user} has successfully connected to Discord!')
        print(f'The bot is currently active in {len(client.guilds)} server(s):')

        for guild in client.guilds:
            print(f'- {guild.name} (ID: {guild.id})')

        # Attempt to sync commands for each guild
        failed_guilds = []
        for guild in client.guilds:
            retry_count = 0
            while True:
                try:
                    await client.tree.sync(guild=guild)
                    print(f'Successfully synced commands for guild: {guild.name}')
                    break
                except discord.errors.HTTPException as e:
                    if e.status == 429:
                        retry_after = e.response.headers.get('Retry-After', 5)
                        retry_after = int(retry_after)
                        retry_count += 1
                        logger.warning(f"Rate limited while syncing commands for guild: {guild.name}. Retrying in {retry_after} seconds. Retry attempt: {retry_count}")
                        await asyncio.sleep(retry_after)
                    else:
                        logger.error(f'Failed to sync commands for guild: {guild.name}. Error: {e}')
                        failed_guilds.append(guild.name)
                        break
                except Exception as e:
                    logger.error(f'Failed to sync commands for guild: {guild.name}. Error: {e}')
                    failed_guilds.append(guild.name)
                    break

        if failed_guilds:
            logger.warning("Failed to sync commands for the following guild(s):")
            for guild_name in failed_guilds:
                logger.warning(f'- {guild_name}')
        else:
            logger.info("Successfully synced commands for all guilds.")

        try:
            await client.tree.sync()
            logger.info("Successfully synced commands globally.")
        except discord.errors.HTTPException as e:
            if e.status == 429:
                retry_after = e.response.headers.get('Retry-After', 5)
                retry_after = int(retry_after)
                logger.warning(f"Rate limited while syncing commands globally. Retrying in {retry_after} seconds.")
                await asyncio.sleep(retry_after)
                await client.tree.sync()
            else:
                logger.error(f'Failed to sync commands globally. Error: {e}')
        except Exception as e:
            logger.error(f'Failed to sync commands globally. Error: {e}')

        # Update bot's presence to indicate it's ready
        await client.change_presence(activity=client.activity)

        print('Bot is ready and operational!')
        
    @client.tree.command(name="hostinfo", description="Get information about a host.")
    async def hostinfo(interaction: discord.Interaction, host_ip: str):
        try:
            host_info = client.shodan.host(host_ip)
            await client.send_split_messages(interaction, f"IP: {host_info['ip_str']}\nOS: {host_info.get('os', 'Unknown')}")
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="protocols", description="List supported protocols.")
    async def protocols(interaction: discord.Interaction):
        try:
            protocol_list = client.shodan.protocols()
            formatted_protocols = "\n".join([f"- {protocol}" for protocol in protocol_list])

            await client.send_split_messages(interaction, formatted_protocols)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="shodan", description="Advanced and basic Shodan queries. Use `/help` for examples.")
    async def search(interaction: discord.Interaction):
        try:
            # Log the user and guild information
            user = interaction.user.name
            guild_name = interaction.guild.name if interaction.guild else "Direct Message"
            # logger.info(f"{user} initiated a Shodan search from {guild_name}")

            modal = QueryModal(title="Shodan Search Query")
            await interaction.response.send_modal(modal)

        except discord.HTTPException as e:
            logger.error(f"HTTP error while sending the modal to {user} in {guild_name}: {e}")
            await handle_errors(interaction, e, "HTTP Error")

        except Exception as e:
            logger.error(f"Unexpected error while processing the search command for {user} in {guild_name}: {e}")
            await handle_errors(interaction, e)
            
    @client.tree.command(name="searchcity", description="Search Shodan by city.")
    async def searchcity(interaction: discord.Interaction, city: str):
        city = city.strip()
        
        try:
            result = client.shodan.search(f"city:\"{city}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchorg", description="Search Shodan by organization.")
    async def searchorg(interaction: discord.Interaction, organization: str):
        try:
            await interaction.response.defer(ephemeral=False)
            result = client.shodan.search(f"org:\"{organization}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchport", description="Search Shodan by port.")
    async def searchport(interaction: discord.Interaction, port: int):
        try:
            await interaction.response.defer(ephemeral=False)
            result = client.shodan.search(f"port:{port}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchcountry", description="Search Shodan by country using a 2-letter country code (e.g., 'US' for the United States).")
    async def searchcountry(interaction: discord.Interaction, country_code: str):
        try:
            # Convert country code to uppercase to ensure case-insensitivity
            country_code = country_code.upper()

            # Ensure the country code is valid
            if len(country_code) != 2:
                await interaction.response.send_message("Please provide a valid 2-letter country code (e.g., 'US' for the United States).", ephemeral=True)
                return

            result = client.shodan.search(f"country:\"{country_code}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="exploitsearch", description="Search for known vulnerabilities using a term.")
    async def exploitsearch(interaction: discord.Interaction, term: str):
        try:
            exploit_search = client.shodan.exploits.search(term)
            
            if 'matches' in exploit_search and exploit_search['matches']:
                top_exploits = exploit_search['matches'][:10]
                replies = []
                
                for exploit in top_exploits:
                    description = exploit.get('description', 'No description available.').strip()
                    source = exploit.get('source', 'Unknown source')
                    date = exploit.get('date', 'Unknown date')
                    exploit_type = exploit.get('type', 'Unknown type')
                    
                    detailed_info = (f"**Description:** {description}\n"
                                    f"**Source:** {source}\n"
                                    f"**Date:** {date}\n"
                                    f"**Type:** {exploit_type}\n"
                                    f"---")
                    replies.append(detailed_info)

                message = "\n".join(replies)
                await client.send_split_messages(interaction, message)
            else:
                await interaction.followup.send("No exploits found for that term.")
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(
        name="listtags", 
        description="Get Shodan Exploits tags. Specify size (1-100). E.g., `/listtags 5`."
    )
    async def listtags(interaction: discord.Interaction, size: int = 10):
        """
        Retrieves a list of popular exploit tags from Shodan based on a specified size.
        """
        try:
            if not 1 <= size <= 100:
                await interaction.response.send_message(
                    "The provided size is out of bounds. Please specify a value between 1 and 100.",
                    ephemeral=True
                )
                return

            tags = client.shodan.exploits.tags(size=size)
            tag_list = ", ".join([tag['value'] for tag in tags['matches']])
            
            if not tag_list:
                message = "No popular exploit tags found."
            elif size == 1:
                message = f"The most popular exploit tag is: {tag_list}"
            else:
                message = f"Here are the top {size} popular exploit tags: {tag_list}"

            await interaction.followup.send(message)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="searchnetblock", description="Search devices in a specific netblock.")
    async def searchnetblock(interaction: discord.Interaction, netblock: str):
        try:
            result = client.shodan.search(f"net:{netblock}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
                        
    @client.tree.command(name="searchproduct", description="Search devices associated with a specific product.")
    async def searchproduct(interaction: discord.Interaction, product: str):
        try:
            result = client.shodan.search(f"product:{product}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="searchssl", description="Search for domains associated with a specific SSL certificate hash.")
    async def searchssl(interaction: discord.Interaction, ssl_hash: str):
        try:
            result = client.shodan.search(f"ssl.cert.fingerprint:{ssl_hash}")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="searchisp", description="Search devices associated with a specific ISP.")
    async def searchisp(interaction: discord.Interaction, isp: str):
        try:
            result = client.shodan.search(f"isp:\"{isp}\"")
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)
            
    @client.tree.command(name="searchgeo", description="Search devices around specific GPS coordinates.")
    async def searchgeo(interaction: discord.Interaction, latitude: float, longitude: float, radius: int = 10):
        await interaction.response.defer(ephemeral=True)
        
        try:
            result = client.shodan.search(f"geo:{latitude},{longitude},{radius}")
            if not result.get('matches', []):
                no_results_message = (f"No devices found around the coordinates "
                                    f"Latitude: {latitude}, Longitude: {longitude} within a radius of {radius} km.")
                await interaction.followup.send(content=no_results_message)
                return
            
            await process_shodan_results(interaction, result)
        except shodan.APIError as e:
            await handle_errors(interaction, e, "Shodan API Error")
        except Exception as e:
            await handle_errors(interaction, e)

    @client.tree.command(name="help", description="Displays a list of available commands.")
    async def help_command(interaction: discord.Interaction):
        embed = discord.Embed(title="Available Commands", description="Here are the commands you can use:", color=0x3498db)
        
        # Basic Commands Header
        embed.add_field(name="🟢 Basic Commands", value="Commands for common tasks.", inline=False)
        
        basic_commands_description = "\n".join([
            f"{command}: {description}" 
            for command, description in {
                "/shodan": "General use of shodan. This is the main command.",
                "/hostinfo": "Get information about a host.",
                "/protocols": "List supported protocols.",
                "/searchcity": "Search Shodan by city.",
                "/searchorg": "Search Shodan by organization.",
                "/searchport": "Search Shodan by port.",
                "/searchcountry": "Search Shodan by country.",
                "/exploitsearch": "Search for known vulnerabilities using a term.",
                "/listtags": "List popular tags.",
                "/searchnetblock": "Search devices in a specific netblock.",
                "/searchproduct": "Search devices associated with a specific product.",
                "/searchssl": "Search for domains associated with a specific SSL certificate hash.",
                "/searchisp": "Search devices associated with a specific ISP.",
                "/searchgeo": "Search devices around specific GPS coordinates."
            }.items()
        ])
        embed.add_field(name="Commands & Descriptions", value=basic_commands_description, inline=False)
        
        # Advanced Search Command Header
        embed.add_field(name="🔴 Advanced Command", value="**Command**: \n`/shodan\nSearch Shodan. All options will be provided.", inline=False)
        
        embed.add_field(name="Examples of Basic Searches", value=(
            "- Single IP: `192.168.1.1`\n"
            "- Domain: `example.com`\n"
            "- Product/Service: `nginx`"
        ), inline=False)
        
        embed.add_field(name="Examples of Advanced Queries", value=(
            "- IP Range: `ip:18.9.47.0-18.9.47.255`\n"
            "- Network: `net:18.9.47.0/24`\n"
            "- SSL Cert Subject: `ssl.cert.subject.cn:stellar.mit.edu`\n"
            "- Headers & HTML:\n"
            "  - By Title: `http.title:\"Massachusetts Institute of Technology\"` - Searches for specific titles in HTTP responses.\n"
            "  - By HTML Content: `http.html:'ua-1592615'` - Looks within the content of HTML pages.\n"
            "- Webcams & IoT:\n"
            "  - Search for vulnerable cams like `wyze`, `webcamxp 5`, or more specific like:\n"
            "  -    \"`Server:yawcam\" \"Mime-Type:text/html`\"\n"
            "  - Webcam in ASN: `screenshot.label:webcam asn:AS45102`\n"
            "  - With Screenshot: `has_screenshot:true`"
        ), inline=False)
        
        await interaction.response.send_message(embed=embed, ephemeral=False)

if __name__ == "__main__":
    config = load_config()
    if check_configurations(config):
        client = aclient(config.get("SHODAN_KEY"))
        setup_bot_commands()  
        client.run(config.get("TOKEN"))
