# polis-client-participation

The part of polis that conversation participants see.

## Installation

### Dependencies

* node `11.15.0`
* npm `7.0.15`

### Setup

```sh
n 11.15.0
npm install -g npm@7.0
npm install
cp polis.config.template.js polis.config.js
npm run build:prod
```

Note:

So... you might think that you should now be able to go to
`http://localhost:5001` and see the polis interface. However, this is not the
case. Because of preprocessing required of the `index.html` file before it will
load (including the embedding of the initial data payload in the html), it is
necessary that the application be accessed through a running instance of the
your polis-server.

Also note that the polisServer process will need to know via its config the port
on which this, the participation client code, will be available. If you don't
mess with any of the default port settings you shouldn't have to worry about all
this nonsense. Just know that if you do, you will then need to update these port
variables in multiple places.

## Troubleshooting

If you get an error that looks something like
`Error: watch /home/csmall/code/polisClientParticipation/js ENOSPC` trying to
run, this may be because your system has too many watches active. If you see
this, try running
`echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf && sudo sysctl -p`
to increase the number of available watches on your system.

## Deployment

Before pushing to s3: `gulp dist`

Then run `npm run deploy:preprod` or `npm run deploy:prod` scripts to deploy to
preprod and prod environments respectively.

### Other Requirements

For gulp-ruby-sass to enable `sourcemap` options, it requires Sass >= 3.3.0
