const path = require('path')
const webpack = require('webpack')

module.exports = function () {
    return {
        mode: 'production',
        devtool: 'source-map',
        entry: {
            'encryption': [path.join(__dirname, '/src/encryption.js')]
        },
        output: {
            path: path.join(__dirname, './lib'),
            filename: '[name].js',
            library: {
                name: 'encryption',
                type: 'umd',
                export: 'default'
            },
            libraryTarget: 'umd',
            globalObject: 'this'
        },
        module: {
            rules: [
                {
                    test: /\.js?$/,
                    loader: 'babel-loader',
                    exclude: /node_modules/
                }
            ]
        },
        plugins: [
            new webpack.DefinePlugin({
                'process.env.NODE_ENV': JSON.stringify('production')
            })
        ],
        optimization: {
            minimize: true
        }
    }
}
