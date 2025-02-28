# Version: 1.0.0
# Author : Mouad Kommir <mouadkommir@gmail.com>

# Get release version
RELEASE=$(grep '^version' pyproject.toml | sed -E 's/version\s*=\s*"([^"]+)"/\1/')
echo "Generating a release for version 'v$RELEASE'"

# Creating a release tag
git tag "v$RELEASE"
git push origin "v$RELEASE"

# Create release
gh release create "v$RELEASE" --title "Version v$RELEASE" --notes "Automatically Generated."

 # Generate distribution files
python -m build

# Upload dist files to release.
gh release upload "v$RELEASE" dist/*

# Remove dist directory.
rm -rf dist/
