# build-scripts
Script to set up the build environment for RDK platforms
# Usage
# Build the project
To set up the build environment and build an image, run the following commands:
```
MACHINE=<target-machine> source ./scripts/setup-environment
bitbake <image-target>
```
- Replace `<target-machine>` with the desired machine configuration.
- Replace `<image-target>` with the specific image or build target you want to create.
