#!/usr/bin/env bash
# Render an HTML card to PNG at 2x. Usage: render.sh name height
set -e; cd "$(dirname "$0")"
google-chrome --headless=new --disable-gpu --no-sandbox --hide-scrollbars --force-device-scale-factor=2 \
  --window-size=1600,"$2" --screenshot="../$1.png" "$1.html" >/dev/null 2>&1
python3 -c "import struct;d=open('../$1.png','rb').read(24);print('$1', struct.unpack('>II',d[16:24]))"
