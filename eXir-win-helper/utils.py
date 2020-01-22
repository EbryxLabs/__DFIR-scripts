import logging
import colorlog


def setup_logger(log_fmt="%(log_color)s%(asctime)s:%(levelname)s:%(message)s", log_file_name=".output.log", level='DEBUG', start_with_empty_log_file=True):

	# Create an empty log file
	if start_with_empty_log_file: 
		with open(log_file_name, 'w') as o: pass

	formatter = colorlog.ColoredFormatter(
		log_fmt,
		datefmt='%D'
	)

	logger = logging.getLogger()

	handler2 = logging.FileHandler(log_file_name)
	handler = logging.StreamHandler()
	handler.setFormatter(formatter)
	logger.addHandler(handler)
	logger.addHandler(handler2)
	logger.setLevel(level)

	return logger