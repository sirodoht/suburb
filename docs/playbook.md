# Server playbook for Ubuntu 20.04.5 LTS

## General server

```sh
# user:root
apt update
useradd -m -s /bin/bash polis

TODO:
passwd polis

apt install -y postgresql g++ git make python python-dev libpq-dev
sudo -i -u postgres
# user:postgres
createuser polis

psql
postgres=# ALTER USER polis CREATEDB;
\q
```

```sh
# user:root
curl -L https://raw.githubusercontent.com/tj/n/master/bin/n -o n
bash n lts
npm install -g n
```

## polis/server

```sh
# user:root
su - polis
# user:polis
cd server
git clone https://github.com/sirodoht/polis.git
cd polis/server/
createdb polis
psql
\i postgres/migrations/000000_initial.sql
\i postgres/migrations/000001_update_pwreset_table.sql
\i postgres/migrations/000002_add_xid_constraint.sql
\q
```

## polis/client-admin

```sh
# user:root
n 11.15.0
npm install -g npm@7.0
# user:polis
su - polis
cd polis/client-admin
npm install
cp polis.config.template.js polis.config.js
npm run build
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
npm run build:prod
```
