/**
 * This code represents the Attribute Pool Object of the original Etherpad.
 * 这段代码标识原始Etherpad的属性池对象
 * 90% of the code is still like in the original Etherpad
 * 90%的代码和原始Etherpad相同
 * Look at https://github.com/ether/pad/blob/master/infrastructure/ace/www/easysync2.js
 * You can find a explanation what a attribute pool is here:
 * https://github.com/ether/etherpad-lite/blob/master/doc/easysync/easysync-notes.txt
 */

/*
 * Copyright 2009 Google Inc., 2011 Peter 'Pita' Martischka (Primary Technology Ltd)
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

/*
  An AttributePool maintains a mapping from [key,value] Pairs called
  Attributes to Numbers (unsigened integers) and vice versa. These numbers are
  used to reference Attributes in Changesets.

  AttributePool维护一个从[key,value]对调用的映射
  属性为数字(无符号整型)，反之亦然。这些数字是
  用于引用变更集中的属性。
*/

var AttributePool = function () {
  this.numToAttrib = {}; // e.g. {0: ['foo','bar']}，数字->属性数组
  this.attribToNum = {}; // e.g. {'foo,bar': 0}，属性->数字，属性为字符串拼接
  this.nextNum = 0; // 下一个数字
};

/**
 * 放入属性
 * 参数：
 * attrib 属性名
 * dontAddIfAbsent 不存在时不进行添加
 * 返回值：
 * 该属性对应的数字
 */
AttributePool.prototype.putAttrib = function (attrib, dontAddIfAbsent) {
  var str = String(attrib);
  if (str in this.attribToNum) {
    return this.attribToNum[str];
  }
  if (dontAddIfAbsent) {
    return -1;
  }
  var num = this.nextNum++;
  this.attribToNum[str] = num;
  this.numToAttrib[num] = [String(attrib[0] || ''), String(attrib[1] || '')];
  return num;
};

/**
 * 获取数字对应的属性key和value
 */
AttributePool.prototype.getAttrib = function (num) {
  var pair = this.numToAttrib[num];
  if (!pair) {
    return pair;
  }
  return [pair[0], pair[1]]; // return a mutable copy
};

/**
 * 根据num获取属性key
 */
AttributePool.prototype.getAttribKey = function (num) {
  var pair = this.numToAttrib[num];
  if (!pair) return '';
  return pair[0];
};

/**
 * 根据num获取属性值
 */
AttributePool.prototype.getAttribValue = function (num) {
  var pair = this.numToAttrib[num];
  if (!pair) return '';
  return pair[1];
};

/**
 * 遍历每一个num的key和value
 */
AttributePool.prototype.eachAttrib = function (func) {
  for (var n in this.numToAttrib) {
    var pair = this.numToAttrib[n];
    func(pair[0], pair[1]);
  }
};

/**
 * 将当前信息存储到json中
 */
AttributePool.prototype.toJsonable = function () {
  return {
    numToAttrib: this.numToAttrib,
    nextNum: this.nextNum
  };
};

/**
 * 从json解析信息
 */
AttributePool.prototype.fromJsonable = function (obj) {
  this.numToAttrib = obj.numToAttrib;
  this.nextNum = obj.nextNum;
  this.attribToNum = {};
  for (var n in this.numToAttrib) {
    this.attribToNum[String(this.numToAttrib[n])] = Number(n);
  }
  return this;
};


module.exports = AttributePool;
