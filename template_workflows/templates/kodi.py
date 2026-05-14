# System info
device = "{time} T:{T} {level} <{category}>:     Device {device_number} m_deviceName :{name}m_displayName :{display_name}m_displayNameExtra:{display_name_extra}m_deviceType :{type}m_channels :{channels}m_sampleRates :{sample_rates}m_dataFormats :{data_formats}m_streamTypes :{stream_types}"
file_contents = "{time} T:{T} {level} <{category}>: Contents of {file} are... {contents}"
ffmpeg_version = "{time} T:{T} {level} <{category}>: FFmpeg version/source: {version}"
host_cpu = "{time} T:{T} {level} <{category}>: Host CPU: {cpu}, {cores} cores available"
kodi_compiled = "{time} T:{T} {level} <{category}>: Kodi compiled {compiled_date} by {compiler} for {platform}"
mapped_directory = "{time} T:{T} {level} <{category}>: {kodi_directory} is mapped to: {local_directory}"
product = "{time} T:{T} {level} <{category}>: Product: {product}, Device: {device} Board: {board} Manufacturer: {manufacturer} Brand: {brand} Model: {model} Hardware: {hardware}"
starting_kodi = "{time} T:{T} {level} <{category}>: Starting Kodi ({version}). Platform: {platform}"
using_release = "{time} T:{T} {level} <{category}>: Using Release {release}"
new_cache_gui_settings = "{time} T:{T} {level} <{category}>: New Cache GUI Settings (replacement of cache in {replaced_cache}) are: Buffer Mode: {buffer_mode} Memory Size: {memory_size} Read Factor: {read_factor} x Chunk Size : {chunk_size}"

# Program actions
thread = "{time} T:{T} {level} <{category}>: {action}"
program_action = "{time} T:{T} {level} <{category}>: {program}::{action}"


# General
closing = "{time} T:{T} {level} <{category}>: Closing {info}"
creating = "{time} T:{T} {level} <{category}>: Creating {info}"
deleting = "{time} T:{T} {level} <{category}>: Deleting {info}"
deleting_2 = "{time} T:{T} {level} <{category}>: deleting {info}"
opening = "{time} T:{T} {level} <{category}>: Opening {info}"
running = "{time} T:{T} {level} <{category}>: Running {info}"
stopping = "{time} T:{T} {level} <{category}>: Stopping {info}"
graphics_library = "{time} T:{T} {level} <{category}>: {graphics_type}_{feature} = {info}"
load = "{time} T:{T} {level} <{category}>:   load {info}"
loaded = "{time} T:{T} {level} <{category}>: Loaded {info}"
loading = "{time} T:{T} {level} <{category}>: Loading {config}"
loading_2 = "{time} T:{T} {level} <{category}>: loading {config}"
update = "{time} T:{T} {level} <{category}>: Update{attribute}: {info}"
mediacodec_decoder = "{time} T:{T} {level} <{category}>: Mediacodec decoder: {decoder}"
remote_mapping = "{time} T:{T} {level} <{category}>: * {action} remote mapping for {device}"
skipped_duplicate_messages = "{time} T:{T} {level} <{category}>: Skipped {number} duplicate messages.."
service = "{time} T:{T} {level} <{category}>: [{service_name}] {info}"


debug_message = "{time} T:{T} debug <{category}>: {message}"
warning_message = "{time} T:{T} warning <{category}>: {message}"
error_message = "{time} T:{T} error <{category}>: {message}"

debug_templates = [
    [debug_message, "debug", "debug"]
]

warning_templates = [
    [warning_message, "warning", "warning"]
]

error_templates = [
    [error_message, "error", "error"]
]


program_action_templates = [
    [thread, "thread", "thread"],
    [program_action, "program_action", "::"],

]

general_templates = [
    [closing, "closing", "Closing"],
    [creating, "creating", "Creating"],
    [deleting, "deleting", "Deleting"],
    [deleting_2, "deleting", "deleting"],
    [opening, "opening", "Opening"],
    [running, "running", "Running"],
    [stopping, "stopping", "Stopping"],
    [mediacodec_decoder, "mediacodec_decoder", "Mediacodec decoder"],
    [graphics_library, "graphics_library", "GL_"],
    [loading, "loading", "Loading"],
    [loading_2, "loading", "loading"],
    [load, "load", "load"],
    [loaded, "loaded", "Loaded"],
    [update, "update", "Update"],
    [remote_mapping, "remote_mapping", "remote mapping"],
    [skipped_duplicate_messages, "duplicate_messages", "Skipped"],
    [service, "service", ">: ["]
]


system_info_templates = [
    [device, "device", "Device"],
    [file_contents, "file_contents", "Contents"],
    [ffmpeg_version, "ffmpeg_version", "FFmpeg"],
    [host_cpu, "host_cpu", "Host CPU"],
    [kodi_compiled, "kodi_compiled", "Kodi compiled"],
    [mapped_directory, "mapped_directory", "is mapped to"],
    [product, "product", "Product"],
    [using_release, "using_release", "Using Release"],
    [starting_kodi, "starting_kodi", "Starting Kodi"],
    [new_cache_gui_settings, "new_cache_gui_settings", "New Cache GUI Settings"]
]

base_kodi_templates = debug_templates + warning_templates + error_templates + program_action_templates  + general_templates + system_info_templates