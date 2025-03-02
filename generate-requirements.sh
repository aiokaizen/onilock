# Version: 1.0.0
# Author : Mouad Kommir <mouadkommir@gmail.com>

# Generate requirements.txt
poetry export --without-hashes --format=requirements.txt --output=requirements.txt
poetry export --without-hashes --format=requirements.txt --with dev --output=all_requirements.txt
