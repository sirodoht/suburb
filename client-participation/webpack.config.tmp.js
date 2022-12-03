const path = require("path")
const webpack = require("webpack")
const CopyPlugin = require("copy-webpack-plugin")
const CompressionPlugin = require('compression-webpack-plugin')
const HtmlWebPackPlugin = require('html-webpack-plugin')
const EventHooksPlugin = require('event-hooks-webpack-plugin')
const LodashReplacementPlugin = require('lodash-webpack-plugin')
const HandlebarsPlugin = require('handlebars-webpack-plugin')
const lodashTemplate = require('lodash.template')
const glob = require('glob')
const fs = require('fs')
const pkg = require('./package.json')

const polisConfig = require('./polis.config')
const TerserPlugin = require("terser-webpack-plugin")

const outputDirectory = 'disttmp'

/**
 * Generates .headersJson files alongside files served by the file-server. Reading these files instructs file-server
 * what HTML headers should be added to each file.
 * 
 * @deprecated
 */
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
    writeHeadersJson('js/*.js', headersData)
    writeHeadersJson('*.js', headersData)
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
  return {
    entry: [
      './js/main',
      './css/polis_main.scss'
    ],
    output: {
      publicPath: '/',
      filename: `js/participation_bundle.[chunkhash:8].js`,
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
        'Backbone': 'backbone', // FIXME: Is this actually necessary?
        'Backbone': 'custom-backbone',
        '_': 'underscore',
        'Handlebones': 'handlebones',
        'markdown': 'markdown',
        'VisView': 'visview'
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
          { from: 'node_modules/font-awesome/fonts/**/*', to: './fonts/[name][ext]' }
        ]
      }),
      new HtmlWebPackPlugin({
        template: path.resolve(__dirname, 'public/index.html'),
        filename: 'index.html',
        templateParameters: {
          domainWhitelist: `["${polisConfig.domainWhitelist.join('","')}"]`,
          versionString: pkg.version,
          fbAppId: polisConfig.FB_APP_ID,
          d3Filename: 'd3.min.js', // FIXME: Needed?
        }
      }),
      new LodashReplacementPlugin({
        currying: true,
        flattening: true,
        paths: true,
        placeholders: true,
        shorthands: true
      }),
      // Only compress and create headerJson files during production builds.
      ...((isDevBuild || isDevServer) ? [] : [
        // new CompressionPlugin({
        //   test: /\.js$/,
        //   filename: '[path][base]',
        //   deleteOriginalAssets: true
        // }),
        new EventHooksPlugin({
          afterEmit: () => {
            console.log('Writing *.headersJson files...')
            writeHeadersJsonForOutputFiles()
          }
        })
      ])
    ],
    // Only minify during production builds
    optimization: {
      minimize: !isDevBuild,
      minimizer: [new TerserPlugin()]
    },
    module: {
      rules: [
        {
          test: /\.(handlebars|hbs)$/,
          exclude: /node_modules/,
          loader: 'handlebars-loader',
          options: {
            ignorePartials: true // We load partials at runtime so ignore at compile-time
          }
        },
        {
          test: /\.m?js$/,
          exclude: /node_modules/,
          use: {
            loader: 'babel-loader',
            options: {
              presets: ['@babel/preset-env', '@babel/preset-react'],
            },
          },
        },
        {
          test: /\.(png|jpg|gif|svg)$/,
          exclude: /node_modules/,
          use: ['file-loader'],
        },
        {
          test: /\.mdx?$/,
          exclude: /node_modules/,
          use: ['babel-loader', '@mdx-js/loader']
        },
        {
          test: /\.s[ac]ss$/,
          exclude: /node_modules/,
          use: [
            {
              loader: 'file-loader',
              options: { outputPath: 'css/', name: 'polis.css' }
            },
            'sass-loader'
          ]
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
