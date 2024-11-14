# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n 2> /dev/null || true

clear

# Execute all scripts in /etc/update-motd.d/
if [ -d /etc/update-motd.d/ ]; then
  for script in /etc/update-motd.d/*; do
    if [ -x "$script" ]; then
      "$script" || echo "Failed to execute $script"
    fi
  done
fi
