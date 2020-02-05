/**
 * The DB Module provides a database initalized with the settings
 * provided by the settings module
 * 这个DB模块提供了一个数据库初始化，设置被设置模块提供
 */

/*
 * 2011 Peter 'Pita' Martischka (Primary Technology Ltd)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS-IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var ueberDB = require("ueberdb2");
var settings = require("../utils/Settings");
var log4js = require('log4js');
const util = require("util");

// set database settings
// 设置数据库设置
let db = new ueberDB.database(settings.dbType, settings.dbSettings, null, log4js.getLogger("ueberDB"));

/**
 * The UeberDB Object that provides the database functions
 * UeberDB对象，提供数据库功能
 */
exports.db = null;

/**
 * Initalizes the database with the settings provided by the settings module
 * 根据设置模块初始化数据库设置
 * @param {Function} callback
 */
exports.init = function() {
  // initalize the database async
  // 异步初始化数据库
  return new Promise((resolve, reject) => {
    db.init(function(err) {
      if (err) {
        // there was an error while initializing the database, output it and stop
        // 初始化数据库出错，则打印错误，并停止程序
        console.error("ERROR: Problem while initalizing the database");
        console.error(err.stack ? err.stack : err);
        process.exit(1);
      } else {
        // everything ok, set up Promise-based methods
        // 一切顺利，设置异步化方法
        ['get', 'set', 'findKeys', 'getSub', 'setSub', 'remove', 'doShutdown'].forEach(fn => {
          exports[fn] = util.promisify(db[fn].bind(db));
        });

        // set up wrappers for get and getSub that can't return "undefined"
        // 给get 和 getSub设置包装，不能返回undefined
        let get = exports.get;
        exports.get = async function(key) {
          let result = await get(key);
          return (result === undefined) ? null : result;
        };

        let getSub = exports.getSub;
        exports.getSub = async function(key, sub) {
          let result = await getSub(key, sub);
          return (result === undefined) ? null : result;
        };

        // exposed for those callers that need the underlying raw API
        // 对那些需要底层API的调用者公开
        exports.db = db;
        resolve();
      }
    });
  });
}
