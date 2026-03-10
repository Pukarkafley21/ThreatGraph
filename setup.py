from setuptools import setup, find_packages

setup(
    name="threatgraph",
    version="1.0.0",
    description="Autonomous Threat Investigation Engine — turn raw logs into attack graphs",
    author="Your Name",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "streamlit>=1.35.0",
        "pandas>=2.0.0",
        "networkx>=3.3",
        "plotly>=5.22.0",
        "openai>=1.30.0",
        "scikit-learn>=1.4.0",
        "numpy>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "threatgraph=threatgraph.cli:main",
        ],
    },
)
