[![Build Status](https://travis-ci.org/tejado/pgoapi.svg?branch=master)](https://travis-ci.org/tejado/pgoapi)

# pgoapi - a pokemon go api lib in python
pgoapi is a client/api/demo for Pokemon Go by https://github.com/tejado.  
It allows automatic parsing of requests/responses by finding the correct protobuf objects over a naming convention and will return the response in a parsed python dictionary format.   

 * This is unofficial - USE AT YOUR OWN RISK !
 * I don't play pokemon go !
 * No bot/farming code included !

## Feature Support
 * Python 2 and 3
 * Google/PTC auth
 * Address parsing for GPS coordinates
 * Allows chaining of RPC calls
 * Re-auth if ticket expired
 * Check for server side-throttling
 * Thread-safety
 * Advanced logging/debugging
 * Uses [POGOProtos](https://github.com/AeonLucid/POGOProtos)
 * Mostly all available RPC calls (see [API reference](https://docs.pogodev.org) on the wiki)

## Documentation
Documentation is available at the github [pgoapi wiki](https://wiki.pogodev.org).

## Requirements
 * Python 2 or 3
 * requests
 * protobuf (>=3)
 * gpsoauth
 * geopy (only for pokecli demo)
 * s2sphere (only for pokecli demo)

## Use
To use this api as part of a python project using setuptools/pip, modify your requirements.txt file to include:
```
git+https://github.com/pogodevorg/pgoapi.git@develop#egg=pgoapi
```

If you are not using setuptools/pip, follow the instructions in the Contributing section below to clone this repository and then install pgoapi using the appropriate method for your project.

## Contributing
Contributions are highly welcome. Please use github or [Discord](https://discord.pogodev.org) for it!

You can get started by cloning this repository. Note that as pgoapi uses [git submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) you must perform a recursive clone:

| Protocol | Command |
| -------- | ------- |
| HTTPS | `git clone --recursive https://github.com/pogodevorg/pgoapi.git` |
| SSH   | `git clone --recursive git@github.com:pogodevorg/pgoapi.git` |

If you already have a copy of the repository you can use `git submodule update --init` to fetch and update the submodules.

Once you have cloned the repository, switch to the `develop` branch. To merge your changes back into the main repository, make a pull request to `develop`.

## Credits
[Mila432](https://github.com/Mila432/Pokemon_Go_API) for the login secrets  
[elliottcarlson](https://github.com/elliottcarlson) for the Google Auth PR  
[AeonLucid](https://github.com/AeonLucid/POGOProtos) for improved protos  
[AHAAAAAAA](https://github.com/AHAAAAAAA/PokemonGo-Map) for parts of the s2sphere stuff  
[mikeres0](https://github.com/mikeres0) for the slack channel including auto signup  
[DeirhX](https://github.com/DeirhX) for thread-safety

## Ports
[Node Port](https://github.com/Armax/Pokemon-GO-node-api) by Arm4x  
[Node Port - pogobuf](https://github.com/cyraxx/pogobuf) by cyraxx 

[![Analytics](https://ga-beacon.appspot.com/UA-1911411-4/pgoapi.git/README.md?pixel&useReferer)](https://github.com/igrigorik/ga-beacon)
