const path = require("path")
const webpack = require("webpack")
const CopyPlugin = require("copy-webpack-plugin")
const HtmlWebPackPlugin = require('html-webpack-plugin')
const EventHooksPlugin = require('event-hooks-webpack-plugin')
const LodashReplacementPlugin = require('lodash-webpack-plugin')
const HandlebarsPlugin = require('handlebars-webpack-plugin')
const lodashTemplate = require('lodash.template')
const glob = require('glob')
const fs = require('fs')

const polisConfig = require('./polis.config')
const TerserPlugin = require("terser-webpack-plugin")

const outputDirectory = 'disttmp'

function writeHeadersJsonForOutputFiles() {
  function writeHeadersJson(matchGlob, headersData = {}) {
    const files = glob.sync(path.resolve(__dirname, outputDirectory, matchGlob))
    files.forEach((f, i) => {
      const headersFilePath = f + '.headersJson'
      fs.writeFileSync(headersFilePath, JSON.stringify(headersData))
    })
  }

  function writeHeadersJsonHtml() {
    const headersData = {
      'x-amz-acl': 'public-read',
      'Content-Type': 'text/html; charset=UTF-8',
      'Cache-Control': 'no-cache'
    }
    writeHeadersJson('*.html', headersData)
  }

  function writeHeadersJsonJs() {
    const headersData = {
      'x-amz-acl': 'public-read',
      'Content-Encoding': 'gzip',
      'Content-Type': 'application/javascript',
      'Cache-Control':
        'no-transform,public,max-age=31536000,s-maxage=31536000'
    }
    writeHeadersJson('static/js/*.js?(.map)', headersData)
  }

  function writeHeadersJsonMisc() {
    writeHeadersJson('favicon.ico')
  }

  writeHeadersJsonHtml()
  writeHeadersJsonJs()
  writeHeadersJsonMisc()
}


module.exports = (env, options) => {
  var isDevBuild = options.mode === 'development'
  var isDevServer = process.env.WEBPACK_SERVE
  var chunkHash = '[chunkhash:8]' // Webpack magically assigns this to a unique string on compile
  var cacheBusterFragment = (isDevBuild || isDevServer) ? '' : `.${chunkHash}` // Used in filenames to 'cache bust'
  return {
    entry: ['./js/main'],
    output: {
      publicPath: '/',
      filename: `static/js/participation_bundle${cacheBusterFragment}.js`,
      path: path.resolve(__dirname, outputDirectory),
      clean: true
    },
    resolve: {
      extensions: ['.js', '.css', '.png', '.svg'],
      alias: {
        'jquery': path.resolve(__dirname, 'js/3rdparty/jquery.min.js'),
        'handlebars': path.resolve(__dirname, 'node_modules/handlebars-v1/dist/handlebars.runtime.js'),
        'backbone': path.resolve(__dirname, 'node_modules/backbone/backbone'), // FIXME: Needed?
        'custom-backbone': path.resolve(__dirname, 'js/net/backbonePolis'),
        'underscore': path.resolve(__dirname, 'node_modules/underscore/underscore'), // FIXME: Needed?
        'handlebones': path.resolve(__dirname, 'node_modules/handlebones/handlebones'),
        'markdown': path.resolve(__dirname, 'node_modules/markdown/lib/markdown.js'),
        'visview': path.resolve(__dirname, 'js/lib/VisView'),
        // 'bootstrap-affix': path.resolve(__dirname, 'node_modules/bootstrap-sass/assets/javascripts/bootstrap/affix')
      }
    },
    devServer: {
      historyApiFallback: true,
      // TODO: Set up API proxy later for server component.
      // See: https://webpack.js.org/configuration/dev-server/#devserverproxy
      // proxy: {
      //   '/api': {
      //   target: 'https://pol.is',
      //   secure: false,
      //   },
      // },
    },
    plugins: [
      // Define some globals
      new webpack.ProvidePlugin({
        '$': 'jquery',
        'jQuery': 'jquery',
        'Handlebars': 'handlebars',
        'Backbone': 'backbone',
        'Backbone': 'custom-backbone',
        '_': 'underscore',
        'Handlebones': 'handlebones',
        'markdown': 'markdown',
        'VisView': 'visview'
        // 'bootstrap_affix': 'bootstrap-affix'
      }),
      new CopyPlugin({
        patterns: [
          { from: 'public', globOptions: { ignore: ['**/index.html'] } },
          { from: 'api', globOptions: { ignore: ['**/embed.js'] } },
          { 
            from: 'api/embed.js',
            transform(content, absoluteFrom) {
              return lodashTemplate(content.toString())({ polisHostName: polisConfig.SERVICE_HOSTNAME })
            }
          },
          { from: 'node_modules/font-awesome/fonts/**/*', to: 'fonts' }
        ]
      }),
      new HtmlWebPackPlugin({
        template: path.resolve(__dirname, 'public/index.html'),
        filename: 'index.html',
        templateParameters: {
          domainWhitelist: `["${polisConfig.domainWhitelist.join('","')}"]`,
          versionString: chunkHash,
          basepath: '', // FIXME: Needed?
          fbAppId: polisConfig.FB_APP_ID,
          d3Filename: 'd3.min.js', // FIXME: Needed?
          basepath_visbundle: '' // FIXME: Needed?
        }
      }),
      new LodashReplacementPlugin({
        currying: true,
        flattening: true,
        paths: true,
        placeholders: true,
        shorthands: true
      }),
      // Only create headerJson files during production builds.
      ...((isDevBuild || isDevServer) ? [] : [
        new EventHooksPlugin({
          afterEmit: () => {
            console.log('Writing *.headersJson files...')
            writeHeadersJsonForOutputFiles()
          }
        })
      ])
    ],
    // Only compress during production builds
    optimization: {
      minimize: !isDevBuild,
      minimizer: [new TerserPlugin()]
    },
    module: {
      rules: [
        {
          test: /\.(handlebars|hbs)$/,
          loader: 'handlebars-loader',
          options: {
            ignorePartials: true
          }
        },
        {
          test: /\.m?js$/,
          exclude: /(node_modules|bower_components)/,
          use: {
            loader: 'babel-loader',
            options: {
              presets: ['@babel/preset-env', '@babel/preset-react'],
            },
          },
        },
        {
          test: /\.(png|jpg|gif|svg)$/,
          use: ['file-loader'],
        },
        {
          test: /\.mdx?$/,
          use: ['babel-loader', '@mdx-js/loader']
        },
        {
          test: /\.s[ac]ss$/,
          use: ['style-loader', 'css-loader']
        }
      ]
    }
  }
}

// module.exports = {
//   // devtool: "source-map",
//   entry: [
//     "./vis2/vis2"
//   ],
//   output: {
//     path: path.join(__dirname, "dist_foo"),
//     filename: "vis_bundle.js",
//     publicPath: "SET_THIS_FROM_GULP"
//   },
//   mode: 'production',
//   optimization: {
//     minimize: true,
//   },
//   module: {
//     rules: [
//       {
//         test: /\.js$/,
//         loader: "babel-loader",
//         include: path.join(__dirname, "vis2"),
//       }
//     ]
//   }
// };
