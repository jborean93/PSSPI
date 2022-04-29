# PSSPI

[![Test workflow](https://github.com/jborean93/PSSPI/workflows/Test%20PSSPI/badge.svg)](https://github.com/jborean93/PSSPI/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/PSSPI/branch/main/graph/badge.svg?token=b51IOhpLfQ)](https://codecov.io/gh/jborean93/PSSPI)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/PSSPI.svg)](https://www.powershellgallery.com/packages/PSSPI)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/PSSPI/blob/main/LICENSE)

See [about_PSSPI](docs/en-US/about_PSSPI.md) for more details.

## Documentation

Documentation for this module and details on the cmdlets included can be found [here](docs/en-US/PSSPI.md).

## Requirements

These cmdlets have the following requirements

* PowerShell v7.0 or newer
* Windows

## Installing

The easiest way to install this module is through
[PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview).

You can install this module by running;

```powershell
# Install for only the current user
Install-Module -Name PSSPI -Scope CurrentUser

# Install for all users
Install-Module -Name PSSPI -Scope AllUsers
```

## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the changes.
To build this module run `.\build.ps1 -Task Build` in PowerShell.
To test a build run `.\build.ps1 -Task Test` in PowerShell.
This script will ensure all dependencies are installed before running the test suite.
