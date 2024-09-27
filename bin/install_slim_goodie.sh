# Source me

# Conda install steps credit: https://gist.github.com/gwangjinkim/f13bf596fefa7db7d31c22efd1627c7a


# Create a Conda environment named SLIM_GOODIE if $1 is not set


if [[ "$1" == "" ]]; then

    conda env create -f slim_goodie_env.yaml
    if [[ $? -ne 0 ]]; then
        echo "\n\n\n\n\n\tERROR\n\t\t Failed to create conda environment. Please check the error message above and try again.\n"
        sleep 3
        return 1
    else
        echo "Conda environment SLIM_GOODIE created successfully."
    fi
    mkdir -p ~/.config/rclone/ && touch ~/.config/rclone/rclone.conf && cat env/rclone.conf >> ~/.config/rclone/rclone.conf 
    
    conda activate SLIM_GOODIE
    if [[ $? -ne 0 ]]; then
        echo "\n\n\n\n\n\tERROR\n\t\t Failed to activate conda environment. Please check the error message above and try again.\n"
        sleep 3
        return 1
    else
        echo "Conda environment SLIM_GOODIE activated successfully."
    fi
fi

export PGPORT=5445
echo "SHELL IS: $SHELL"

# Create database
initdb -D $PGDATA

# start server
pg_ctl -D $PGDATA -o "-p $PGPORT" -l $PGDATA/db.log start 

PGPORT=5445 psql -U $PGUSER -d postgres << EOF

ALTER USER $PGUSER PASSWORD '$PGPASSWORD';

EOF

createdb --owner $USER $PGDBNAME

# create the schema/db from the template


echo "\n\n\nSlim Goodie Installation Is Complete. You may start the slim_goodie ui with 
source run_slim_goodie_ui.sh' and then navigate to http://localhost:8918 in your browser.\n\n\n"
echo "complete"