# Server playbook for Ubuntu 20.04.5 LTS

This is a server playbook on how to setup a production environment for polis.

## General server

```sh
# user:root
apt update
useradd -m -s /bin/bash polis
passwd polis

apt install -y postgresql g++ git make python python-dev libpq-dev direnv

# node.js
curl -L https://raw.githubusercontent.com/tj/n/master/bin/n -o n
bash n lts
npm install -g n
```

## polis/database

```sh
sudo -i -u postgres
# user:postgres
createuser polis
psql
```

```sql
postgres=# ALTER USER polis CREATEDB;
\q
```

## polis/server

```sh
# user:root
su - polis
n 11.15.0

# user:polis
cd server
git clone https://github.com/sirodoht/polis.git
cd polis/server/

cp .envrc.example .envrc
npm run build
npm start
```

## polis/client-admin

```sh
# user:root
n 11.15.0
npm install -g npm@7.0

# user:polis
su - polis
cd polis/client-admin
cp .envrc.example .envrc
npm install
cp polis.config.template.js polis.config.js
npm run build
npm run deploy:prod
```

## polis/client-participation

```sh
# user:root
n 11.15.0
npm install -g npm@7.0

# user:polis
su - polis
cd polis/client-admin
npm install
node node_modules/node-sass/scripts/install.js
npm rebuild node-sass
npm install

cp polis.config.template.js polis.config.js
npm run build
npm run deploy:prod
```

## polis/client-report

```sh
# user:root
n 11.15.0
npm install -g npm@7.0

# user:polis
su - polis
cd polis/client-report
cp .envrc.example .envrc
cp polis.config.template.js polis.config.js
npm install
npm install # yes, twice
npm run build
npm run deploy:prod
```

## polis/file-server

```sh
# user:root
n 11.15.0
npm install -g npm@7.0

# user:polis
su - polis
cd polis/file-server
cp fs_config.template.json fs_config.json
npm install

# bring all js bundles here
mkdir build
make
```

## polis/math

```sh
# user:root
apt install -y openjdk-17-jre rlwrap
curl -O https://download.clojure.org/install/linux-install-1.11.1.1155.sh
chmod +x linux-install-1.11.1.1155.sh
./linux-install-1.11.1.1155.sh
rm linux-install-1.11.1.1155.sh
clojure -A:dev -P
clojure -M:run full
```

## polis/caddy

```sh
# user:polis
cd polis/caddy
cp .envrc.example .envrc
make devserver

systemctl status caddy --full --no-pager  # check logs
```

## After reboot

```sh
cd polis/

cd file-server/
npm start

cd ../math/
clojure -M:run full

cd ../server/
npm start
```

## Development

```sh
cd polis/

cd file-server/
npm start

cd ../math/
clojure -X:dev-poller

cd ../server/
npm run dev

cd ../caddy/
make devserver
```
