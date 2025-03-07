from importlib.resources import files
import pandas as pd

# Sample Log Files for testing built-in types
log_file_path = "template_log_parser.sample_log_files"

debian_sample_log = files(log_file_path).joinpath("debian_sample_log.log")

omada_sample_log = files(log_file_path).joinpath("omada_sample_log.log")

omv_sample_log = files(log_file_path).joinpath("omv_sample_log.log")
omv_debian_sample_log = files(log_file_path).joinpath("omv_debian_sample_log.log")

pfsense_sample_log = files(log_file_path).joinpath('pfsense_sample_log.log')

pihole_sample_log = files(log_file_path).joinpath("pihole_sample_log.log")
pihole_debian_sample_log = files(log_file_path).joinpath("pihole_debian_sample_log.log")

synology_sample_log = files(log_file_path).joinpath("synology_sample_log.log")

# Create new files by adding debian to omv and pihole respectively.
pihole_files = [pihole_sample_log, debian_sample_log]
with open(str(pihole_debian_sample_log), "w") as outfile:
    for file in pihole_files:
        with open(str(file)) as infile:
            outfile.write(infile.read())

omv_files = [omv_sample_log, debian_sample_log]
with open(str(omv_debian_sample_log), "w") as outfile:
    for file in omv_files:
        with open(str(file)) as infile:
            outfile.write(infile.read())

# Sample df that contains columns suitable for testing of built-in column functions
sample_df = pd.DataFrame(
    {
        "utc_time": ["2024-09-15T11:44:51+01:00", "2024-09-15T12:44:51+01:00"],
        "data": ["45MB", "132.0KB"],
        "time": ["2024-09-15T11:44:51+01:00", "2024-09-15T12:44:51+01:00"],
        "client_name_and_mac": ["name_1:E4-A8-EF-4A-40-DC", "name2:b8-3e-9d-41-0b-6d"],
        "time_elapsed": ["26h5m", "30s"],
        "ip_address_raw": ["192.168.0.1", "(10.0.0.1)"],
        "delimited_data": ["10, 10", "11, 11"],
        "delimited_by_periods": ["10.10", "11.11"],
    }
)
