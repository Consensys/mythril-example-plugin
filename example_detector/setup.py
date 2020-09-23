import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="myth_example_detector",
    version="0.0.1",
    author="Joran Honig",
    author_email="joran.honig@consensys.net",
    description="An example mythril plugin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ConsenSys/mythril-example-plugin",
    packages=[
        "myth_example_detector"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    # ===========================================
    # The entry_points field is used to register the plugin with mythril
    #
    # Right now we register only one plugin for the "mythril.plugins" entry point,
    # note that you can add multiple plugins.
    # ===========================================
    entry_points={
        "mythril.plugins": [
            "myth_example_detector = myth_example_detector:OwnershipDetector",
        ],
    },
    python_requires='>=3.6',
)