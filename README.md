# slim goodie: a lightweight oauth2 credential checking http server

## Oauth2 Authentication w/Supabase
* [supabase config](docs/supabase.md).


# Installation

## Prerequisites

### Hardware Supported
_see build test badges above for all supported platforms_
* Mac (14+) 
  * `brew install coreutils` is required for the `gtimeout` command for some rclone functionality. run `alias timeout=gtimeout` to use the gtimeout w/zsh.
* Ubuntu 22+


### Conda
* Conda (you may swap in mamba if you prefer). [Installing conda](https://docs.conda.io/en/latest/miniconda.html):

### Supabase
* [Please follow the supabase configuration instructions here](documents/supabase.md).


## Very Quickest Start
_assumes you have completed the prerequisites_

```bash
# Clone the repository
git clone git@github.com:Daylily-Informatics/slim_goodie.git
cd slim_goodie

# This will attempt to build the conda env
source bin/install_slim_goodie.sh 
 

# Activate conda env
conda activate SLIM_GOODIE

# Start the Slim GoodieUI
source run_slim_goodie_ui.sh
```

## Testing
* with pytest

```bash

conda activate SLIM_GOODIE

# no tests yet
# pytest

```


# Authors
* [John Major:li](https://www.linkedin.com/in/john--major/) aka [iamh2o:gh](http://github.com/iamh2o)


# License
* MIT
 
