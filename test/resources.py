import logging
from importlib.resources import files

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

log_file_path = "test.sample_log_files"

debian_sample_log = files(log_file_path).joinpath("debian_sample_log.log")

omada_sample_log = files(log_file_path).joinpath("omada_sample_log.log")

omv_sample_log = files(log_file_path).joinpath("omv_sample_log.log")
omv_debian_sample_log = files(log_file_path).joinpath("omv_debian_sample_log.log")

pfsense_sample_log = files(log_file_path).joinpath("pfsense_sample_log.log")

pihole_sample_log = files(log_file_path).joinpath("pihole_sample_log.log")

synology_sample_log = files(log_file_path).joinpath("synology_sample_log.log")

ubuntu_sample_log = files(log_file_path).joinpath("ubuntu_sample_log.log")
ubuntu_debian_sample_log = files(log_file_path).joinpath("ubuntu_debian_sample_log.log")

# Create new files by adding debian to omv, pihole, and ubuntu
file_types = [
    [omv_sample_log, omv_debian_sample_log],
    [ubuntu_sample_log, ubuntu_debian_sample_log]
]

for (original_log, merged_log) in file_types:
    with open(str(merged_log), 'w') as outfile:
        for file in [original_log, debian_sample_log]:
            with open(str(file)) as infile:
                outfile.write(infile.read())
