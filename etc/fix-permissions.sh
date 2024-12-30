#!/bin/bash


chmod 640 /etc/letsencrypt/archive/daylily.cloud/* || echo "chmod failed"
chown root:ssl-users /etc/letsencrypt/archive/daylily.cloud/* || echo "chown failed"
chmod 750 /etc/letsencrypt/live/daylily.cloud/ || echo "chmod failed"
chmod 640 /etc/letsencrypt/live/daylily.cloud/* || echo "chmod failed"

# Set this up as a service eventually

sleep 1
sudo -u daylily tmux send-keys -t bloom C-c
sudo lsof -i :8911 | grep gunicorn | awk '{print $2}' | xargs -r sudo kill -9 > /dev/null 2>&1 || echo "kill failed"
sleep 1
sudo lsof -i :8911 | grep uvicorn | awk '{print $2}' | xargs -r sudo kill -9 > /dev/null 2>&1 || echo "kill failed"
sleep 1
# Restart the server to apply the new certificate
sudo -u daylily tmux send-keys -t bloom "source /home/daylily/miniconda3/bin/activate BLOOM && /home/daylily/projects/bloom/run_bloomui.sh" Enter
sleep 1


sudo -u daylily tmux send-keys -t slim_goodie C-c
sudo lsof -i :8912 | grep gunicorn | awk '{print $2}' | xargs -r sudo kill -9 > /dev/null 2>&1 || echo "kill failed"
sleep 1
sudo lsof -i :8912 | grep uvicorn | awk '{print $2}' | xargs -r sudo kill -9 > /dev/null 2>&1 || echo "kill failed"
sleep 1
# Restart the server to apply the new certificate
sudo -u daylily tmux send-keys -t slim_goodie "source /home/daylily/miniconda3/bin/activate SLIM_GOODIE && /home/daylily/projects/slim_goodie/run_slimgoodie.sh" Enter
sleep 1


sudo -u daylily tmux send-keys -t bangateapot C-c
sudo lsof -i :8913 | grep gunicorn | awk '{print $2}' | xargs -r sudo kill -9 > /dev/null 2>&1 || echo "kill failed"
sleep 1
sudo lsof -i :8913 | grep uvicorn | awk '{print $2}' | xargs -r sudo kill -9 > /dev/null 2>&1 || echo "kill failed"
sleep 1
# Restart the server to apply the new certificate
sudo -u daylily tmux send-keys -t bangateapot "source /home/daylily/miniconda3/bin/activate SLIM_GOODIE && /home/daylily/projects/bangateapot/run_bangateapot.sh" Enter
sleep 1
