/*
 * This is the Changeset library copied from the old Etherpad with some modifications to use it in node.js
 * Can be found in https://github.com/ether/pad/blob/master/infrastructure/ace/www/easysync2.js
 * 这是Changeset库从老的Etherpad复制出来，并且进行了一些修改以便于用于node.js
 */

/**
 * This code is mostly from the old Etherpad. Please help us to comment this code.
 * This helps other people to understand this code better and helps them to improve it.
 * TL;DR COMMENTS ON THIS FILE ARE HIGHLY APPRECIATED
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

var AttributePool = require("./AttributePool");

/**
 * ==================== General Util Functions =======================
 * 通用工具方法
 */

/**
 * This method is called whenever there is an error in the sync process
 * 无论任何时候，只要在处理同步时出现异常，这个方法将会被调用
 * 
 * @param msg {string} Just some message
 */
exports.error = function error(msg) {
  var e = new Error(msg);
  e.easysync = true;
  throw e;
};

/**
 * This method is used for assertions with Messages
 * if assert fails, the error function is called.
 * 
 * 这个方法用于断言信息，如果断言失败，错误方法将被调用
 * 
 * @param b {boolean} assertion condition
 * @param msgParts {string} error to be passed if it fails
 */
exports.assert = function assert(b, msgParts) {
  if (!b) {
    var msg = Array.prototype.slice.call(arguments, 1).join('');
    exports.error("Failed assertion: " + msg);
  }
};

/**
 * Parses a number from string base 36
 * 解析一个数字根据base36算法
 * @param str {string} string of the number in base 36
 * @returns {int} number
 */
exports.parseNum = function (str) {
  return parseInt(str, 36);
};

/**
 * Writes a number in base 36 and puts it in a string
 * 转换一个数字为base36的字符串
 * @param num {int} number
 * @returns {string} string
 */
exports.numToString = function (num) {
  return num.toString(36).toLowerCase();
};

/**
 * Converts stuff before $ to base 10(注释错误)
 * 
 * $前的文字替换成 base 36 字符串
 * 
 * @obsolete not really used anywhere??
 * @param cs {string} the string
 * @return integer
 */
exports.toBaseTen = function (cs) {
  var dollarIndex = cs.indexOf('$');
  var beforeDollar = cs.substring(0, dollarIndex);
  var fromDollar = cs.substring(dollarIndex);
  return beforeDollar.replace(/[0-9a-z]+/g, function (s) {
    return String(exports.parseNum(s));
  }) + fromDollar;
};


/**
 * ==================== Changeset Functions =======================
 * Changeset方法
 */

/**
 * returns the required length of the text before changeset
 * can be applied
 * 
 * 返回应用changeset所需的文本长度
 * 
 * 返回
 * 
 * @param cs {string} String representation of the Changeset
 */
exports.oldLen = function (cs) {
  return exports.unpack(cs).oldLen;
};

/**
 * returns the length of the text after changeset is applied
 * 
 * 返回changeset被应用之后的文本长度
 * 
 * @param cs {string} String representation of the Changeset
 */
exports.newLen = function (cs) {
  return exports.unpack(cs).newLen;
};

/**
 * this function creates an iterator which decodes string changeset operations
 * 
 * 这个方法创建一个迭代器，用于解码字符串Changeset的操作
 * 
 * @param opsStr {string} String encoding of the change operations to be performed
 * 编码成字符串的被执行的变更操作
 * @param optStartIndex {int} from where in the string should the iterator start
 * 从什么地方字符串应该被迭代开始
 * @return {Op} type object iterator
 */
exports.opIterator = function (opsStr, optStartIndex) {
  // console.info("opsStr:" + opsStr + ", optStartIndex:" + optStartIndex);
  // 样例：|7=bi*0+3
  var regex = /((?:\*[0-9a-z]+)*)(?:\|([0-9a-z]+))?([-+=])([0-9a-z]+)|\?|/g;
  var startIndex = (optStartIndex || 0);
  var curIndex = startIndex;
  var prevIndex = curIndex;

  function nextRegexMatch() {
    prevIndex = curIndex;
    var result;
    regex.lastIndex = curIndex;
    result = regex.exec(opsStr);
    curIndex = regex.lastIndex;
    if (result[0] == '?') {
      exports.error("Hit error opcode in op stream");
    }
    // console.info("nextRegexMatch-result:" + result);
    return result;
  }
  var regexResult = nextRegexMatch();
  var obj = exports.newOp();

  function next(optObj) {
    var op = (optObj || obj);
    // console.info("Changeset.js - opIterator - next - regexResult[0]:" + regexResult[0]);
    // |7+bi
    if (regexResult[0]) {
      // console.info("Changeset.js - opIterator - next - regexResult[1]:" + regexResult[1]);
      // [1] = 空
      // console.info("Changeset.js - opIterator - next - regexResult[2]:" + regexResult[2]);
      // [2] = 7
      // console.info("Changeset.js - opIterator - next - regexResult[3]:" + regexResult[3]);
      // [3] = +
      // console.info("Changeset.js - opIterator - next - regexResult[4]:" + regexResult[4]);
      // [4] = bi
      op.attribs = regexResult[1];
      op.lines = exports.parseNum(regexResult[2] || 0);
      op.opcode = regexResult[3];
      op.chars = exports.parseNum(regexResult[4]);
      regexResult = nextRegexMatch();
    } else {
      exports.clearOp(op);
    }
    // console.info("next-op:" + JSON.stringify(op));
    return op;
  }

  function hasNext() {
    return !!(regexResult[0]);
  }

  function lastIndex() {
    return prevIndex;
  }
  return {
    next: next,
    hasNext: hasNext,
    lastIndex: lastIndex
  };
};

/**
 * Cleans an Op object
 * 清空一个op对象
 * @param {Op} object to be cleared
 */
exports.clearOp = function (op) {
  op.opcode = '';
  op.chars = 0;
  op.lines = 0;
  op.attribs = '';
};

/**
 * Creates a new Op object
 * 创建一个新的op对象
 * @param optOpcode the type operation of the Op object
 */
exports.newOp = function (optOpcode) {
  return {
    opcode: (optOpcode || ''),
    chars: 0,
    lines: 0,
    attribs: ''
  };
};

/**
 * Clones an Op
 * 克隆一个op对象
 * @param op Op to be cloned
 */
exports.cloneOp = function (op) {
  return {
    opcode: op.opcode,
    chars: op.chars,
    lines: op.lines,
    attribs: op.attribs
  };
};

/**
 * Copies op1 to op2
 * 将op1复制到op2
 * @param op1 src Op
 * @param op2 dest Op
 */
exports.copyOp = function (op1, op2) {
  op2.opcode = op1.opcode;
  op2.chars = op1.chars;
  op2.lines = op1.lines;
  op2.attribs = op1.attribs;
};

/**
 * Writes the Op in a string the way that changesets need it
 * 写入一个op对象到字符串，该字符串用于放入changeset中
 */
exports.opString = function (op) {
  // just for debugging
  if (!op.opcode) return 'null';
  var assem = exports.opAssembler();
  assem.append(op);
  return assem.toString();
};

/**
 * Used just for debugging
 * 把op打印出来，用于调试
 */
exports.stringOp = function (str) {
  // just for debugging
  return exports.opIterator(str).next();
};

/**
 * Used to check if a Changeset if valid
 * 
 * 用于检查一个changeset是否是合法的
 * 
 * @param cs {Changeset} Changeset to be checked
 */
exports.checkRep = function (cs) {
  // doesn't check things that require access to attrib pool (e.g. attribute order)
  // or original string (e.g. newline positions)
  // 不需要检查的东西，访问attrib pool(如属性顺序)或原始字符串(如换行位置)
  var unpacked = exports.unpack(cs);
  var oldLen = unpacked.oldLen;
  var newLen = unpacked.newLen;
  var ops = unpacked.ops;
  var charBank = unpacked.charBank;

  var assem = exports.smartOpAssembler();
  var oldPos = 0;
  var calcNewLen = 0;
  var numInserted = 0;
  var iter = exports.opIterator(ops);
  while (iter.hasNext()) {
    var o = iter.next();
    switch (o.opcode) {
    case '=':
      oldPos += o.chars;
      calcNewLen += o.chars;
      break;
    case '-':
      oldPos += o.chars;
      exports.assert(oldPos <= oldLen, oldPos, " > ", oldLen, " in ", cs);
      break;
    case '+':
      {
        calcNewLen += o.chars;
        numInserted += o.chars;
        exports.assert(calcNewLen <= newLen, calcNewLen, " > ", newLen, " in ", cs);
        break;
      }
    }
    assem.append(o);
  }

  calcNewLen += oldLen - oldPos;
  charBank = charBank.substring(0, numInserted);
  while (charBank.length < numInserted) {
    charBank += "?";
  }

  assem.endDocument();
  var normalized = exports.pack(oldLen, calcNewLen, assem.toString(), charBank);
  exports.assert(normalized == cs, 'Invalid changeset (checkRep failed)');

  return cs;
}


/**
 * ==================== Util Functions =======================
 * 工具方法
 */

/**
 * creates an object that allows you to append operations (type Op) and also
 * compresses them if possible
 * 
 * 创建一个对象允许你添加操作（op类型）和同时压缩他们，如果可能的话
 * 
 */
exports.smartOpAssembler = function () {
  // Like opAssembler but able to produce conforming exportss
  // from slightly looser input, at the cost of speed.
  // Specifically:
  // - merges consecutive operations that can be merged
  // - strips final "="
  // - ignores 0-length changes
  // - reorders consecutive + and - (which margingOpAssembler doesn't do)
  // 与opAssembler类似，但能够以速度为代价，从稍微宽松的输入生成符合要求的输出。
  // 特别的：
  // - 合并可合并的连续操作
  // - 拿掉最后的"="操作
  // - 忽略0长度的变化
  // - 记录连续的 + 和 - 操作（margingOpAssembler做不到）
  var minusAssem = exports.mergingOpAssembler();
  var plusAssem = exports.mergingOpAssembler();
  var keepAssem = exports.mergingOpAssembler();
  var assem = exports.stringAssembler();
  var lastOpcode = '';
  var lengthChange = 0;

  /**
   * 输出keeps中的op操
   */
  function flushKeeps() {
    assem.append(keepAssem.toString());
    keepAssem.clear();
  }

  /**
   * 输出plus和minus中的op操作
   */
  function flushPlusMinus() {
    assem.append(minusAssem.toString());
    minusAssem.clear();
    assem.append(plusAssem.toString());
    plusAssem.clear();
  }

  /**
   * 添加op操作
   * @param {op操作} op 
   */
  function append(op) {
    if (!op.opcode) return;
    if (!op.chars) return;

    if (op.opcode == '-') {
      if (lastOpcode == '=') {
        flushKeeps();
      }
      minusAssem.append(op);
      lengthChange -= op.chars;
    } else if (op.opcode == '+') {
      if (lastOpcode == '=') {
        flushKeeps();
      }
      plusAssem.append(op);
      lengthChange += op.chars;
    } else if (op.opcode == '=') {
      if (lastOpcode != '=') {
        flushPlusMinus();
      }
      keepAssem.append(op);
    }
    lastOpcode = op.opcode;
  }

  function appendOpWithText(opcode, text, attribs, pool) {

    // console.log("appendOpWithText - text : " + text);

    // 创建新Op
    var op = exports.newOp(opcode);

    // 创建属性
    op.attribs = exports.makeAttribsString(opcode, attribs, pool);

    // console.log("appendOpWithText - op : " + JSON.stringify(op));

    // 最后一个换行符的位置
    var lastNewlinePos = text.lastIndexOf('\n');

    // console.log("appendOpWithText - lastNewlinePos : " + lastNewlinePos);

    if (lastNewlinePos < 0) {
      // 没有换行符的情况
      op.chars = text.length;
      op.lines = 0;
      append(op);
    } else {
      // 有换行符的情况，拆成2个op，1个是最后一个换行符之前的字符（包含最后一个换行符），1个是最后一个换行符之后的字符
      op.chars = lastNewlinePos + 1;
      op.lines = text.match(/\n/g).length;

      // console.log("appendOpWithText - op2 : " + JSON.stringify(op));

      append(op);


      op.chars = text.length - (lastNewlinePos + 1);
      op.lines = 0;

      // console.log("appendOpWithText - op3 : " + JSON.stringify(op));

      append(op);
    }
  }

  function toString() {
    flushPlusMinus();
    flushKeeps();
    return assem.toString();
  }

  function clear() {
    minusAssem.clear();
    plusAssem.clear();
    keepAssem.clear();
    assem.clear();
    lengthChange = 0;
  }

  function endDocument() {
    keepAssem.endDocument();
  }

  function getLengthChange() {
    return lengthChange;
  }

  return {
    append: append,
    toString: toString,
    clear: clear,
    endDocument: endDocument,
    appendOpWithText: appendOpWithText,
    getLengthChange: getLengthChange
  };
};

/**
 * 合并Op的汇编器
 */
exports.mergingOpAssembler = function () {
  // This assembler can be used in production; it efficiently
  // merges consecutive operations that are mergeable, ignores
  // no-ops, and drops final pure "keeps".  It does not re-order
  // operations.
  // 这个汇编器可以用于生产环境。它有效的合并连续的可合并的操作，忽略无操作，和删除保留操作。他不会对操作进行重排序。
  var assem = exports.opAssembler();
  var bufOp = exports.newOp();

  // If we get, for example, insertions [xxx\n,yyy], those don't merge,
  // but if we get [xxx\n,yyy,zzz\n], that merges to [xxx\nyyyzzz\n].
  // This variable stores the length of yyy and any other newline-less
  // ops immediately after it.
  // 如果我们获得，例如 插入[xxx\n,yyy]，这个不会合并，但是如果我们获得[xxx\n,yyy,zzz\n]，会合并为[xxx\nyyyzzz\n]。
  // 这个变量存储yyy的长度和紧随其后的任何其他无换行操作
  var bufOpAdditionalCharsAfterNewline = 0;

  function flush(isEndDocument) {

    if (bufOp.opcode) {

      // bufOp存在操作符

      if (isEndDocument && bufOp.opcode == '=' && !bufOp.attribs) {

        // 是文档结尾 并且 bufOp的操作符是 保留 并且 bufOp没有属性
        // final merged keep, leave it implicit
        // 最后合并保持，保持隐式

      } else {

        // 将bufOp加入op编码器
        assem.append(bufOp);
        if (bufOpAdditionalCharsAfterNewline) {
          // 如果最后一行包含额外的字符，则新创建一个bufOp并加入编码器
          bufOp.chars = bufOpAdditionalCharsAfterNewline;
          bufOp.lines = 0;
          assem.append(bufOp);
          bufOpAdditionalCharsAfterNewline = 0;
        }
      }
      bufOp.opcode = '';
    }
  }

  function append(op) {

    // 如果新加入的op不包含文字变化则不处理
    if (op.chars > 0) {

      if (bufOp.opcode == op.opcode && bufOp.attribs == op.attribs) {

        // 缓冲Op对象的操作类型和属性与新加入的op对象相同

        if (op.lines > 0) {

          // op是多行文本

          // bufOp and additional chars are all mergeable into a multi-line op
          // op和额外的字符都合并到一个多行op中
          bufOp.chars += bufOpAdditionalCharsAfterNewline + op.chars;
          bufOp.lines += op.lines;
          bufOpAdditionalCharsAfterNewline = 0;

        } else if (bufOp.lines == 0) {

          // bufOp和op都为单行变化
          // 等价于op.lines == 0 and bufOp.lines == 0

          // both bufOp and op are in-line
          // 将新的op对象的变化文字数量加入bufOp
          bufOp.chars += op.chars;

        } else {

          // 等价于op.lines == 0 and bufOp.lines > 0

          // append in-line text to multi-line bufOp
          // 加入同一行文本到多行bufOp

          bufOpAdditionalCharsAfterNewline += op.chars;

        }

      } else {

        // 缓冲Op对象的操作类型和属性与新加入的op对象不相同

        flush();
        exports.copyOp(op, bufOp);
      }
    }
  }

  function endDocument() {
    flush(true);
  }

  function toString() {
    flush();
    return assem.toString();
  }

  function clear() {
    assem.clear();
    exports.clearOp(bufOp);
  }
  return {
    append: append,
    toString: toString,
    clear: clear,
    endDocument: endDocument
  };
};


/**
 * 将一个op对象集合成字符串数组，并最后格式化成字符串
 */
exports.opAssembler = function () {

  var pieces = [];

  // this function allows op to be mutated later (doesn't keep a ref)
  // 这个方法允许op晚些再变形（不要保持一个引用）

  function append(op) {
    pieces.push(op.attribs);
    if (op.lines) {
      pieces.push('|', exports.numToString(op.lines));
    }
    pieces.push(op.opcode);
    pieces.push(exports.numToString(op.chars));
  }

  function toString() {
    // console.log("pieces.join('') : " + pieces.join(''));
    return pieces.join('');
  }

  function clear() {
    pieces.length = 0;
  }
  return {
    append: append,
    toString: toString,
    clear: clear
  };
};

/**
 * A custom made String Iterator
 * 一个自定义的字符串迭代器
 * @param str {string} String to be iterated over
 */
exports.stringIterator = function (str) {

  // 当前位置
  var curIndex = 0;

  // newLines is the number of \n between curIndex and str.length
  // newLines 是curIndex 到 str.length之间的换行符数量
  var newLines = str.split("\n").length - 1

  /**
   * 获取剩余换行符数量
   */
  function getnewLines(){
    return newLines
  }

  /**
   * 检查剩余字符是否足够
   * @param n
   */
  function assertRemaining(n) {
    exports.assert(n <= remaining(), "!(", n, " <= ", remaining(), ")");
  }

  /**
   * 从curIndex开始，获取n个字符，curIndex前进n个字符，newLines重新计算
   * @param {获取字符数量} n 
   */
  function take(n) {
    assertRemaining(n);
    var s = str.substr(curIndex, n);
    // 计算剩余换行符的数量
    newLines -= s.split("\n").length - 1
    curIndex += n;
    return s;
  }

  /**
   * 从curIndex开始，获取n个字符
   * @param {获取字符数量} n 
   */
  function peek(n) {
    assertRemaining(n);
    var s = str.substr(curIndex, n);
    return s;
  }

  /**
   * 从curIndex开始，跳过n个字符
   * @param {字符数量} n 
   */
  function skip(n) {
    assertRemaining(n);
    curIndex += n;
  }

  /**
   * 计算剩余字符数量
   */
  function remaining() {
    return str.length - curIndex;
  }
  return {
    take: take,
    skip: skip,
    remaining: remaining,
    peek: peek,
    newlines: getnewLines
  };
};

/**
 * A custom made StringBuffer
 * 一个自定义StringBuffer，字符串汇编器
 */
exports.stringAssembler = function () {
  var pieces = [];

  function append(x) {
    pieces.push(String(x));
  }

  function toString() {
    return pieces.join('');
  }
  return {
    append: append,
    toString: toString
  };
};

/**
 * This class allows to iterate and modify texts which have several lines
 * It is used for applying Changesets on arrays of lines
 * Note from prev docs: "lines" need not be an array as long as it supports certain calls (lines_foo inside).
 * 这个类允许迭代和修改多行文本。
 * 用于应用Changesets在行数足上。
 * 来自prev文档的注意:“行”不需要是一个数组，只要它支持某些调用(lines_foo里面)。
 */
exports.textLinesMutator = function (lines) {
  // Mutates lines, an array of strings, in place.
  // Mutation operations have the same constraints as exports operations
  // with respect to newlines, but not the other additional constraints
  // (i.e. ins/del ordering, forbidden no-ops, non-mergeability, final newline).
  // Can be used to mutate lists of strings where the last char of each string
  // is not actually a newline, but for the purposes of N and L values,
  // the caller should pretend it is, and for things to work right in that case, the input
  // to insert() should be a single line with no newlines.
  // 在适当的位置突变行(字符串数组)。
  // 对于换行，变异操作具有与导出操作相同的约束，但其他附加约束
  // （例如：ins/del顺序，禁止无操作，不可合并，最后的换行)。
  // 可用于变异,每个字符串的最后一个字符的字符串列表实际上不是一个换行符,但为了N和L值,
  // 调用者应该假装存在,并且为了让所有事情在这种情况下运行正常,插入操作应该是单独一行并且没有换行。
  var curSplice = [0, 0];
  var inSplice = false;
  // position in document after curSplice is applied:
  // 在curSplice之后的文档位置被应用:
  var curLine = 0,
      curCol = 0;
  // invariant: if (inSplice) then (curLine is in curSplice[0] + curSplice.length - {2,3}) &&
  //            curLine >= curSplice[0]
  // 不变的：如果 inSplice=true 则
  // invariant: if (inSplice && (curLine >= curSplice[0] + curSplice.length - 2)) then
  //            curCol == 0

  function lines_applySplice(s) {
    lines.splice.apply(lines, s);
  }

  function lines_toSource() {
    return lines.toSource();
  }

  function lines_get(idx) {
    if (lines.get) {
      return lines.get(idx);
    } else {
      return lines[idx];
    }
  }
  // can be unimplemented if removeLines's return value not needed

  function lines_slice(start, end) {
    if (lines.slice) {
      return lines.slice(start, end);
    } else {
      return [];
    }
  }

  function lines_length() {
    if ((typeof lines.length) == "number") {
      return lines.length;
    } else {
      return lines.length();
    }
  }

  function enterSplice() {
    curSplice[0] = curLine;
    curSplice[1] = 0;
    if (curCol > 0) {
      putCurLineInSplice();
    }
    inSplice = true;
  }

  function leaveSplice() {
    lines_applySplice(curSplice);
    curSplice.length = 2;
    curSplice[0] = curSplice[1] = 0;
    inSplice = false;
  }

  function isCurLineInSplice() {
    return (curLine - curSplice[0] < (curSplice.length - 2));
  }

  function debugPrint(typ) {
    print(typ + ": " + curSplice.toSource() + " / " + curLine + "," + curCol + " / " + lines_toSource());
  }

  function putCurLineInSplice() {
    if (!isCurLineInSplice()) {
      curSplice.push(lines_get(curSplice[0] + curSplice[1]));
      curSplice[1]++;
    }
    return 2 + curLine - curSplice[0];
  }

  function skipLines(L, includeInSplice) {
    if (L) {
      if (includeInSplice) {
        if (!inSplice) {
          enterSplice();
        }
        for (var i = 0; i < L; i++) {
          curCol = 0;
          putCurLineInSplice();
          curLine++;
        }
      } else {
        if (inSplice) {
          if (L > 1) {
            leaveSplice();
          } else {
            putCurLineInSplice();
          }
        }
        curLine += L;
        curCol = 0;
      }
      //print(inSplice+" / "+isCurLineInSplice()+" / "+curSplice[0]+" / "+curSplice[1]+" / "+lines.length);
/*if (inSplice && (! isCurLineInSplice()) && (curSplice[0] + curSplice[1] < lines.length)) {
  print("BLAH");
  putCurLineInSplice();
}*/
      // tests case foo in remove(), which isn't otherwise covered in current impl
    }
    //debugPrint("skip");
  }

  function skip(N, L, includeInSplice) {
    if (N) {
      if (L) {
        skipLines(L, includeInSplice);
      } else {
        if (includeInSplice && !inSplice) {
          enterSplice();
        }
        if (inSplice) {
          putCurLineInSplice();
        }
        curCol += N;
        //debugPrint("skip");
      }
    }
  }

  function removeLines(L) {
    var removed = '';
    if (L) {
      if (!inSplice) {
        enterSplice();
      }

      function nextKLinesText(k) {
        var m = curSplice[0] + curSplice[1];
        return lines_slice(m, m + k).join('');
      }
      if (isCurLineInSplice()) {
        //print(curCol);
        if (curCol == 0) {
          removed = curSplice[curSplice.length - 1];
          // print("FOO"); // case foo
          curSplice.length--;
          removed += nextKLinesText(L - 1);
          curSplice[1] += L - 1;
        } else {
          removed = nextKLinesText(L - 1);
          curSplice[1] += L - 1;
          var sline = curSplice.length - 1;
          removed = curSplice[sline].substring(curCol) + removed;
          curSplice[sline] = curSplice[sline].substring(0, curCol) + lines_get(curSplice[0] + curSplice[1]);
          curSplice[1] += 1;
        }
      } else {
        removed = nextKLinesText(L);
        curSplice[1] += L;
      }
      //debugPrint("remove");
    }
    return removed;
  }

  function remove(N, L) {
    var removed = '';
    if (N) {
      if (L) {
        return removeLines(L);
      } else {
        if (!inSplice) {
          enterSplice();
        }
        var sline = putCurLineInSplice();
        removed = curSplice[sline].substring(curCol, curCol + N);
        curSplice[sline] = curSplice[sline].substring(0, curCol) + curSplice[sline].substring(curCol + N);
        //debugPrint("remove");
      }
    }
    return removed;
  }

  function insert(text, L) {
    if (text) {
      if (!inSplice) {
        enterSplice();
      }
      if (L) {
        var newLines = exports.splitTextLines(text);
        if (isCurLineInSplice()) {
          //if (curCol == 0) {
          //curSplice.length--;
          //curSplice[1]--;
          //Array.prototype.push.apply(curSplice, newLines);
          //curLine += newLines.length;
          //}
          //else {
          var sline = curSplice.length - 1;
          var theLine = curSplice[sline];
          var lineCol = curCol;
          curSplice[sline] = theLine.substring(0, lineCol) + newLines[0];
          curLine++;
          newLines.splice(0, 1);
          Array.prototype.push.apply(curSplice, newLines);
          curLine += newLines.length;
          curSplice.push(theLine.substring(lineCol));
          curCol = 0;
          //}
        } else {
          Array.prototype.push.apply(curSplice, newLines);
          curLine += newLines.length;
        }
      } else {
        var sline = putCurLineInSplice();
        curSplice[sline] = curSplice[sline].substring(0, curCol) + text + curSplice[sline].substring(curCol);
        curCol += text.length;
      }
      //debugPrint("insert");
    }
  }

  function hasMore() {
    //print(lines.length+" / "+inSplice+" / "+(curSplice.length - 2)+" / "+curSplice[1]);
    var docLines = lines_length();
    if (inSplice) {
      docLines += curSplice.length - 2 - curSplice[1];
    }
    return curLine < docLines;
  }

  function close() {
    if (inSplice) {
      leaveSplice();
    }
    //debugPrint("close");
  }

  var self = {
    skip: skip,
    remove: remove,
    insert: insert,
    close: close,
    hasMore: hasMore,
    removeLines: removeLines,
    skipLines: skipLines
  };
  return self;
};

/**
 * Function allowing iterating over two Op strings.
 * 执行压缩连个op字符串，压缩函数允许在两个op字符串之间迭代
 * @params in1 {string} first Op string 第一个op字符串
 * @params idx1 {int} integer where 1st iterator should start 第一个迭代器的开始index
 * @params in2 {string} second Op string 第二个op字符串
 * @params idx2 {int} integer where 2nd iterator should start 第二个迭代器的开始index
 * @params func {function} which decides how 1st or 2nd iterator 决定第一个或第二个迭代器如何前。
 *         advances. When opX.opcode = 0, iterator X advances to 当opX.opcode = 0, 迭代器X 前进到下一个元素
 *         next element
 *         func has signature f(op1, op2, opOut) 方法的签名
 *             op1 - current operation of the first iterator 第一个迭代器的当前操作
 *             op2 - current operation of the second iterator 第二个迭代器的当前操作
 *             opOut - result operator to be put into Changeset 要
 * @return {string} the integrated changeset
 */
exports.applyZip = function (in1, idx1, in2, idx2, func) {

  // |8+bj -> +1*0+1|8+bi"

  // console.log("Changeset.js - applyZip - in1 : " + JSON.stringify(in1))
  // |8+bj
  // console.log("Changeset.js - applyZip - idx1 : " + JSON.stringify(idx1))
  // 0
  // console.log("Changeset.js - applyZip - in2 : " + JSON.stringify(in2))
  // =1*0+1
  // console.log("Changeset.js - applyZip - idx2 : " + JSON.stringify(idx2))
  // 0

  var iter1 = exports.opIterator(in1, idx1);
  var iter2 = exports.opIterator(in2, idx2);
  var assem = exports.smartOpAssembler();
  var op1 = exports.newOp();
  var op2 = exports.newOp();
  var opOut = exports.newOp();

  while (op1.opcode || iter1.hasNext() || op2.opcode || iter2.hasNext()) {

    // 如果op1.opcode是空，并且iter1有值，则将iter1的值赋值给op1
    if ((!op1.opcode) && iter1.hasNext()) iter1.next(op1);

    // 如果op2.opcode是空，并且iter2有值，则将iter2的值赋值给op2
    if ((!op2.opcode) && iter2.hasNext()) iter2.next(op2);

    // console.log("Changeset.js - applyZip - op1 : " + JSON.stringify(op1))
    // console.log("Changeset.js - applyZip - op2 : " + JSON.stringify(op2))

    // op1 : {"opcode":"+","chars":415,"lines":8,"attribs":""}
    // op2 : {"opcode":"=","chars":1,"lines":0,"attribs":""}

    // op1 : {"opcode":"+","chars":414,"lines":8,"attribs":""}
    // op2 : {"opcode":"+","chars":1,"lines":0,"attribs":"*0"}

    // op1 : {"opcode":"+","chars":414,"lines":8,"attribs":""}
    // op2 : {"opcode":"","chars":1,"lines":0,"attribs":"*0"}

    // 合并op1和op2, opOut是合并结果
    func(op1, op2, opOut);

    // console.log("Changeset.js - applyZip - opOut : " + JSON.stringify(opOut))
    // opOut : {"opcode":"+","chars":1,"lines":0,"attribs":""}
    // opOut : {"opcode":"+","chars":1,"lines":0,"attribs":"*0"}
    // opOut : {"opcode":"+","chars":414,"lines":8,"attribs":""}

    if (opOut.opcode) {
      // 如果opOut存在opcode，则加入op编码器
      //print(opOut.toSource());
      assem.append(opOut);
      opOut.opcode = '';
    }

  }
  assem.endDocument();

  // console.log("Changeset.js - applyZip - assem.toString() : " + JSON.stringify(assem.toString()));
  // +1*0+1|8+bi

  return assem.toString();
};

/**
 * Unpacks a string encoded Changeset into a proper Changeset object
 * 
 * 解压一个被编码为字符串的Changeset到一个完整的Changeset对象
 * 
 * @params cs {string} String encoded Changeset
 * @returns {Changeset} a Changeset class
 */
exports.unpack = function (cs) {
  // 样例Z:d5>2|7=bi=1m*0+2$df
  // $后边为输入的文字
  // >2是新增了2个文字，+2也是新增了2个文字
  // 
  var headerRegex = /Z:([0-9a-z]+)([><])([0-9a-z]+)|/;
  var headerMatch = headerRegex.exec(cs);
  if ((!headerMatch) || (!headerMatch[0])) {
    exports.error("Not a exports: " + cs);
  }
  // headerMatch[1] = d5 = 473
  var oldLen = exports.parseNum(headerMatch[1]);

  // headerMatch[2] = >
  var changeSign = (headerMatch[2] == '>') ? 1 : -1;

  // headerMatch[3] = 2
  var changeMag = exports.parseNum(headerMatch[3]);
  var newLen = oldLen + changeSign * changeMag; // = 475

  // headerMatch[0] = Z:d5>2
  var opsStart = headerMatch[0].length; // 6
  var opsEnd = cs.indexOf("$"); // 17
  if (opsEnd < 0) opsEnd = cs.length;
  return {
    oldLen: oldLen,
    newLen: newLen,
    ops: cs.substring(opsStart, opsEnd), // |7=bi=1m*0+2
    charBank: cs.substring(opsEnd + 1) // df
  };
};

/**
 * Packs Changeset object into a string
 * 打包一个changeset到一个字符串
 * @params oldLen {int} Old length of the Changeset
 * @params newLen {int] New length of the Changeset
 * @params opsStr {string} String encoding of the changes to be made
 * @params bank {string} Charbank of the Changeset
 * @returns {Changeset} a Changeset class
 */
exports.pack = function (oldLen, newLen, opsStr, bank) {
  var lenDiff = newLen - oldLen;
  var lenDiffStr = (lenDiff >= 0 ? '>' + exports.numToString(lenDiff) : '<' + exports.numToString(-lenDiff));
  var a = [];
  a.push('Z:', exports.numToString(oldLen), lenDiffStr, opsStr, '$', bank);
  // console.log("Changeset.js - pack - a.join('') : " + a.join(''));
  return a.join('');
};

/**
 * Applies a Changeset to a string
 * 对一个字符串应用一个Changeset
 * @params cs {string} String encoded Changeset 字符串编码的Changeset
 * @params str {string} String to which a Changeset should be applied 被应用Changeset的字符串
 */
exports.applyToText = function (cs, str) {

  // console.log("Changeset.js - applyToText - csStr : " + JSON.stringify(cs));
  // Z:bj>1=1*0+1$1

  // console.log("Changeset.js - applyToText - str : " + JSON.stringify(str));
  // Welcome to Etherpad!\n\nThis pad text is synchronized as you type, so that everyone viewing this page sees the same text. This allows you to collaborate seamlessly on documents!\n\nGet involved with Etherpad at http://etherpad.org\n\nWarning: DirtyDB is used. This is fine for testing but not recommended for production. -- To suppress these warning messages change suppressErrorsInPadText to true in your settings.json\n\n

  var unpacked = exports.unpack(cs);

  // console.log("Changeset.js - applyToText - csObject : " + JSON.stringify(unpacked));
  //  {"oldLen":415,"newLen":416,"ops":"=1*0+1","charBank":"1"}

  exports.assert(str.length == unpacked.oldLen, "mismatched apply: ", str.length, " / ", unpacked.oldLen);
  var csIter = exports.opIterator(unpacked.ops);
  var bankIter = exports.stringIterator(unpacked.charBank);
  var strIter = exports.stringIterator(str);
  var assem = exports.stringAssembler();
  while (csIter.hasNext()) {
    var op = csIter.next();
    // console.log("Changeset.js - applyToText - op : " + JSON.stringify(op));
    // {"opcode":"=","chars":1,"lines":0,"attribs":""}
    // {"opcode":"+","chars":1,"lines":0,"attribs":"*0"}
    switch (op.opcode) {
      case '+':
      //op is + and op.lines 0: no newlines must be in op.chars op是 加 操作并且没有换行: pad.atext.text不会有换行
      //op is + and op.lines >0: op.chars must include op.lines newlines op是 加 操作并且有换行: pad.atext.text 肯定包含 op.lines个换行符
      if(op.lines != bankIter.peek(op.chars).split("\n").length - 1){
        throw new Error("newline count is wrong in op +; cs:"+cs+" and text:"+str);
      }
      assem.append(bankIter.take(op.chars));
      break;
      case '-':
      //op is - and op.lines 0: no newlines must be in the deleted string op是 减 操作并且op没有换行：pad.atext.text不会有换行
      //op is - and op.lines >0: op.lines newlines must be in the deleted string op是 减 操作并且op有换行：pad.atext.text肯定包含 op.lines个新换行符
      if(op.lines != strIter.peek(op.chars).split("\n").length - 1){
        throw new Error("newline count is wrong in op -; cs:"+cs+" and text:"+str);
      }
      strIter.skip(op.chars);
      break;
    case '=':
      //op is = and op.lines 0: no newlines must be in the copied string 在复制字符串中没有新的换行
      //op is = and op.lines >0: op.lines newlines must be in the copied string op.lines个新的换行肯定在被复制的字符串中
      if(op.lines != strIter.peek(op.chars).split("\n").length - 1){
        throw new Error("newline count is wrong in op =; cs:"+cs+" and text:"+str);
      }
      assem.append(strIter.take(op.chars));
      break;
    }
  }
  assem.append(strIter.take(strIter.remaining()));
  // console.log("Changeset.js - applyToText - assem.toString() : " + JSON.stringify(assem.toString()));
  // W1elcome to Etherpad!\n\nThis pad text is synchronized as you type, so that everyone viewing this page sees the same text. This allows you to collaborate seamlessly on documents!\n\nGet involved with Etherpad at http://etherpad.org\n\nWarning: DirtyDB is used. This is fine for testing but not recommended for production. -- To suppress these warning messages change suppressErrorsInPadText to true in your settings.json\n\n
  return assem.toString();
};

/**
 * applies a changeset on an array of lines
 * @param CS {Changeset} the changeset to be applied
 * @param lines The lines to which the changeset needs to be applied
 */
exports.mutateTextLines = function (cs, lines) {
  var unpacked = exports.unpack(cs);
  var csIter = exports.opIterator(unpacked.ops);
  var bankIter = exports.stringIterator(unpacked.charBank);
  var mut = exports.textLinesMutator(lines);
  while (csIter.hasNext()) {
    var op = csIter.next();
    switch (op.opcode) {
    case '+':
      mut.insert(bankIter.take(op.chars), op.lines);
      break;
    case '-':
      mut.remove(op.chars, op.lines);
      break;
    case '=':
      mut.skip(op.chars, op.lines, ( !! op.attribs));
      break;
    }
  }
  mut.close();
};

/**
 * Composes two attribute strings (see below) into one.
 * 组合两个属性字符串到一个
 * @param att1 {string} first attribute string 第一个属性字符串
 * @param att2 {string} second attribue string 第二个属性字符串
 * @param resultIsMutaton {boolean} 结果是否变化
 * @param pool {AttribPool} attribute pool 属性池
 */
exports.composeAttributes = function (att1, att2, resultIsMutation, pool) {
  // att1 and att2 are strings like "*3*f*1c", asMutation is a boolean.
  // Sometimes attribute (key,value) pairs are treated as attribute presence
  // information, while other times they are treated as operations that
  // mutate a set of attributes, and this affects whether an empty value
  // is a deletion or a change.
  // att1和att2是类似“*3*f*1c”的字符串，asMutation是一个布尔值。有时，属性(键、值)对被视为属性状态信息，而其他时候，它们被视为一组属性发生变化的操作，这将影响空值是删除还是更改。
  // Examples, of the form (att1Items, att2Items, resultIsMutation) -> result
  // 1. ([], [(bold, )], true) -> [(bold, )]
  // 2. ([], [(bold, )], false) -> []
  // 3. ([], [(bold, true)], true) -> [(bold, true)]
  // 4. ([], [(bold, true)], false) -> [(bold, true)]
  // 5. ([(bold, true)], [(bold, )], true) -> [(bold, )]
  // 6. ([(bold, true)], [(bold, )], false) -> []
  // pool can be null if att2 has no attributes.
  // pool可以为空如果att2没有属性
  if ((!att1) && resultIsMutation) {
    // In the case of a mutation (i.e. composing two exportss),
    // an att2 composed with an empy att1 is just att2.  If att1
    // is part of an attribution string, then att2 may remove
    // attributes that are already gone, so don't do this optimization.
    // 上述例子5、6，在一种突变的情况下(即组成两个出口)，一个att2与一个空的att1合并，则只是att2。
    // 如果att1只有属性字符串的一部分，那么att2可能会删除已经消失的属性，所以不要进行这种优化。
    // 也就是，如果att1不存在，并且att1和att2的attribs相同，则返回att2
    return att2;
  }
  if (!att2) return att1;
  var atts = [];
  console.log("Changeset.js - composeAttributes - att1 : " + att1);
  att1.replace(/\*([0-9a-z]+)/g, function (_, a) {
    atts.push(pool.getAttrib(exports.parseNum(a)));
    return '';
  });
  console.log("Changeset.js - composeAttributes - att1 - replace : " + att1);

  console.log("Changeset.js - composeAttributes - att2 : " + att2);
  att2.replace(/\*([0-9a-z]+)/g, function (_, a) {
    var pair = pool.getAttrib(exports.parseNum(a));
    var found = false;
    for (var i = 0; i < atts.length; i++) {
      var oldPair = atts[i];
      if (oldPair[0] == pair[0]) {
        if (pair[1] || resultIsMutation) {
          oldPair[1] = pair[1];
        } else {
          atts.splice(i, 1);
        }
        found = true;
        break;
      }
    }
    if ((!found) && (pair[1] || resultIsMutation)) {
      atts.push(pair);
    }
    return '';
  });

  console.log("Changeset.js - composeAttributes - att2 -replace : " + att2);

  console.log("Changeset.js - composeAttributes - atts : " + JSON.stringify(atts));

  atts.sort();

  console.log("Changeset.js - composeAttributes - atts - sort : " + JSON.stringify(atts));

  var buf = exports.stringAssembler();
  for (var i = 0; i < atts.length; i++) {
    buf.append('*');
    console.log("Changeset.js - composeAttributes - pool.putAttrib(atts[i]) : " + pool.putAttrib(atts[i]));
    buf.append(exports.numToString(pool.putAttrib(atts[i])));
  }

  console.log("Changeset.js - composeAttributes - buf.toString() : " + buf.toString());
  //print(att1+" / "+att2+" / "+buf.toString());
  return buf.toString();
};

/**
 * Function used as parameter for applyZip to apply a Changeset to an
 * attribute
 * 函数，用作applyZip的参数，以便将changeset应用于attribs
 */
exports._slicerZipperFunc = function (attOp, csOp, opOut, pool) {
  // attOp is the op from the sequence that is being operated on, either an
  // attribution string or the earlier of two exportss being composed.
  // pool can be null if definitely not needed.
  // attOp是来自正在操作的序列的op，要么是一个属性字符串，要么是正在组成的两个输出的前面一个。池可以是空的，如果肯定不需要。
  //print(csOp.toSource()+" "+attOp.toSource()+" "+opOut.toSource());

  if (attOp.opcode == '-') {
    // 如果attOp是 减 操作，则直接使用attOp返回，并把attOp的opcode置空
    exports.copyOp(attOp, opOut);
    attOp.opcode = '';
  } else if (!attOp.opcode) {
    // 如果attOp不存在opcode，则直接使用csOp返回，并把csOp的opcode置空
    exports.copyOp(csOp, opOut);
    csOp.opcode = '';
  } else {

    // attOp是 加 或者 保持 操作

    switch (csOp.opcode) {
    case '-':
      {
        if (csOp.chars <= attOp.chars) {

          // 如果csOp的字符数小于attOp

          // delete or delete part
          // 删除或删除部分

          if (attOp.opcode == '=') {
            // 如果attOp的opcode是 保持，则返回csOp
            opOut.opcode = '-';
            opOut.chars = csOp.chars;
            opOut.lines = csOp.lines;
            opOut.attribs = '';
          }

          // 从attOp中减去csOp的值，并置空csOp，如果attOp不存在了，则attOp也要置空
          attOp.chars -= csOp.chars;
          attOp.lines -= csOp.lines;
          csOp.opcode = '';
          if (!attOp.chars) {
            attOp.opcode = '';
          }
        } else {

          // 如果csOp的字符数大于attOp

          // delete and keep going
          // 删除并继续

          // 如果attOp是 保持 操作，则返回attOp的值
          if (attOp.opcode == '=') {
            opOut.opcode = '-';
            opOut.chars = attOp.chars;
            opOut.lines = attOp.lines;
            opOut.attribs = '';
          }

          // 从csOp减去attOp的值，并置空attOp
          csOp.chars -= attOp.chars;
          csOp.lines -= attOp.lines;
          attOp.opcode = '';
        }
        break;
      }
    case '+':
      {
        // insert
        // 如果csOp是插入操作，则直接返回csOp，并置空csOp
        exports.copyOp(csOp, opOut);
        csOp.opcode = '';
        break;
      }
    case '=':
      {
        if (csOp.chars <= attOp.chars) {

          // 如果csOp的字符数小于attOp
          // keep or keep part
          // 保持或保持部分

          // 使用attOp的opcode，和csOp的数值，合并attOp和csOp的属性，并置空csOp，从attOp中减去csOp的值，如果此时attOp没有字符数，则也置空attOp
          opOut.opcode = attOp.opcode;
          opOut.chars = csOp.chars;
          opOut.lines = csOp.lines;
          opOut.attribs = exports.composeAttributes(attOp.attribs, csOp.attribs, attOp.opcode == '=', pool);
          csOp.opcode = '';
          attOp.chars -= csOp.chars;
          attOp.lines -= csOp.lines;
          if (!attOp.chars) {
            attOp.opcode = '';
          }
        } else {
          // keep and keep going
          opOut.opcode = attOp.opcode;
          opOut.chars = attOp.chars;
          opOut.lines = attOp.lines;
          opOut.attribs = exports.composeAttributes(attOp.attribs, csOp.attribs, attOp.opcode == '=', pool);
          attOp.opcode = '';
          csOp.chars -= attOp.chars;
          csOp.lines -= attOp.lines;
        }
        break;
      }
    case '':
      {
        // 如果csOp的opcode是空，则直接返回attOp，并把attOp的opcode置空
        exports.copyOp(attOp, opOut);
        attOp.opcode = '';
        break;
      }
    }
  }
};

/**
 * Applies a Changeset to the attribs string of a AText.
 * 应用一个changeset到Atext的attribs字符串上
 * @param cs {string} Changeset
 * @param astr {string} the attribs string of a AText
 * @param pool {AttribsPool} the attibutes pool
 */
exports.applyToAttribution = function (cs, astr, pool) {
  var unpacked = exports.unpack(cs);

  // console.log("Changeset.js - applyToAttribution - cs : " + JSON.stringify(cs));
  // Z:bj>1=1*0+1$1

  // console.log("Changeset.js - applyToAttribution - astr : " + JSON.stringify(astr));
  // |8+bj

  // console.log("Changeset.js - applyToAttribution - pool : " + JSON.stringify(pool));
  // {"numToAttrib":{"0":["author","a.F3wABRpxZB8PVCGP"]},"attribToNum":{"author,a.F3wABRpxZB8PVCGP":0},"nextNum":1}

  // console.log("Changeset.js - applyToAttribution - unpacked : " + JSON.stringify(unpacked));
  // {"oldLen":415,"newLen":416,"ops":"=1*0+1","charBank":"1"}

  // 压缩并合并两个op字符串，此处astr是当前pad的atext字段的attribs的op字符串，unpacked.op是changeset的op字符串
  return exports.applyZip(astr, 0, unpacked.ops, 0, function (op1, op2, opOut) {
    return exports._slicerZipperFunc(op1, op2, opOut, pool);
  });

};

/*exports.oneInsertedLineAtATimeOpIterator = function(opsStr, optStartIndex, charBank) {
  var iter = exports.opIterator(opsStr, optStartIndex);
  var bankIndex = 0;

};*/

exports.mutateAttributionLines = function (cs, lines, pool) {
  //dmesg(cs);
  //dmesg(lines.toSource()+" ->");
  var unpacked = exports.unpack(cs);
  var csIter = exports.opIterator(unpacked.ops);
  var csBank = unpacked.charBank;
  var csBankIndex = 0;
  // treat the attribution lines as text lines, mutating a line at a time
  var mut = exports.textLinesMutator(lines);

  var lineIter = null;

  function isNextMutOp() {
    return (lineIter && lineIter.hasNext()) || mut.hasMore();
  }

  function nextMutOp(destOp) {
    if ((!(lineIter && lineIter.hasNext())) && mut.hasMore()) {
      var line = mut.removeLines(1);
      lineIter = exports.opIterator(line);
    }
    if (lineIter && lineIter.hasNext()) {
      lineIter.next(destOp);
    } else {
      destOp.opcode = '';
    }
  }
  var lineAssem = null;

  function outputMutOp(op) {
    //print("outputMutOp: "+op.toSource());
    if (!lineAssem) {
      lineAssem = exports.mergingOpAssembler();
    }
    lineAssem.append(op);
    if (op.lines > 0) {
      exports.assert(op.lines == 1, "Can't have op.lines of ", op.lines, " in attribution lines");
      // ship it to the mut
      mut.insert(lineAssem.toString(), 1);
      lineAssem = null;
    }
  }

  var csOp = exports.newOp();
  var attOp = exports.newOp();
  var opOut = exports.newOp();
  while (csOp.opcode || csIter.hasNext() || attOp.opcode || isNextMutOp()) {
    if ((!csOp.opcode) && csIter.hasNext()) {
      csIter.next(csOp);
    }
    //print(csOp.toSource()+" "+attOp.toSource()+" "+opOut.toSource());
    //print(csOp.opcode+"/"+csOp.lines+"/"+csOp.attribs+"/"+lineAssem+"/"+lineIter+"/"+(lineIter?lineIter.hasNext():null));
    //print("csOp: "+csOp.toSource());
    if ((!csOp.opcode) && (!attOp.opcode) && (!lineAssem) && (!(lineIter && lineIter.hasNext()))) {
      break; // done
    } else if (csOp.opcode == '=' && csOp.lines > 0 && (!csOp.attribs) && (!attOp.opcode) && (!lineAssem) && (!(lineIter && lineIter.hasNext()))) {
      // skip multiple lines; this is what makes small changes not order of the document size
      mut.skipLines(csOp.lines);
      //print("skipped: "+csOp.lines);
      csOp.opcode = '';
    } else if (csOp.opcode == '+') {
      if (csOp.lines > 1) {
        var firstLineLen = csBank.indexOf('\n', csBankIndex) + 1 - csBankIndex;
        exports.copyOp(csOp, opOut);
        csOp.chars -= firstLineLen;
        csOp.lines--;
        opOut.lines = 1;
        opOut.chars = firstLineLen;
      } else {
        exports.copyOp(csOp, opOut);
        csOp.opcode = '';
      }
      outputMutOp(opOut);
      csBankIndex += opOut.chars;
      opOut.opcode = '';
    } else {
      if ((!attOp.opcode) && isNextMutOp()) {
        nextMutOp(attOp);
      }
      //print("attOp: "+attOp.toSource());
      exports._slicerZipperFunc(attOp, csOp, opOut, pool);
      if (opOut.opcode) {
        outputMutOp(opOut);
        opOut.opcode = '';
      }
    }
  }

  exports.assert(!lineAssem, "line assembler not finished:"+cs);
  mut.close();

  //dmesg("-> "+lines.toSource());
};

/**
 * joins several Attribution lines
 * @param theAlines collection of Attribution lines
 * @returns {string} joined Attribution lines
 */
exports.joinAttributionLines = function (theAlines) {
  var assem = exports.mergingOpAssembler();
  for (var i = 0; i < theAlines.length; i++) {
    var aline = theAlines[i];
    var iter = exports.opIterator(aline);
    while (iter.hasNext()) {
      assem.append(iter.next());
    }
  }
  return assem.toString();
};

exports.splitAttributionLines = function (attrOps, text) {
  var iter = exports.opIterator(attrOps);
  var assem = exports.mergingOpAssembler();
  var lines = [];
  var pos = 0;

  function appendOp(op) {
    assem.append(op);
    if (op.lines > 0) {
      lines.push(assem.toString());
      assem.clear();
    }
    pos += op.chars;
  }

  while (iter.hasNext()) {
    var op = iter.next();
    var numChars = op.chars;
    var numLines = op.lines;
    while (numLines > 1) {
      var newlineEnd = text.indexOf('\n', pos) + 1;
      exports.assert(newlineEnd > 0, "newlineEnd <= 0 in splitAttributionLines");
      op.chars = newlineEnd - pos;
      op.lines = 1;
      appendOp(op);
      numChars -= op.chars;
      numLines -= op.lines;
    }
    if (numLines == 1) {
      op.chars = numChars;
      op.lines = 1;
    }
    appendOp(op);
  }

  return lines;
};

/**
 * splits text into lines
 * @param {string} text to be splitted
 */
exports.splitTextLines = function (text) {
  return text.match(/[^\n]*(?:\n|[^\n]$)/g);
};

/**
 * compose two Changesets
 * @param cs1 {Changeset} first Changeset
 * @param cs2 {Changeset} second Changeset
 * @param pool {AtribsPool} Attribs pool
 */
exports.compose = function (cs1, cs2, pool) {
  var unpacked1 = exports.unpack(cs1);
  var unpacked2 = exports.unpack(cs2);
  var len1 = unpacked1.oldLen;
  var len2 = unpacked1.newLen;
  exports.assert(len2 == unpacked2.oldLen, "mismatched composition of two changesets");
  var len3 = unpacked2.newLen;
  var bankIter1 = exports.stringIterator(unpacked1.charBank);
  var bankIter2 = exports.stringIterator(unpacked2.charBank);
  var bankAssem = exports.stringAssembler();

  var newOps = exports.applyZip(unpacked1.ops, 0, unpacked2.ops, 0, function (op1, op2, opOut) {
    //var debugBuilder = exports.stringAssembler();
    //debugBuilder.append(exports.opString(op1));
    //debugBuilder.append(',');
    //debugBuilder.append(exports.opString(op2));
    //debugBuilder.append(' / ');
    var op1code = op1.opcode;
    var op2code = op2.opcode;
    if (op1code == '+' && op2code == '-') {
      bankIter1.skip(Math.min(op1.chars, op2.chars));
    }
    exports._slicerZipperFunc(op1, op2, opOut, pool);
    if (opOut.opcode == '+') {
      if (op2code == '+') {
        bankAssem.append(bankIter2.take(opOut.chars));
      } else {
        bankAssem.append(bankIter1.take(opOut.chars));
      }
    }

    //debugBuilder.append(exports.opString(op1));
    //debugBuilder.append(',');
    //debugBuilder.append(exports.opString(op2));
    //debugBuilder.append(' -> ');
    //debugBuilder.append(exports.opString(opOut));
    //print(debugBuilder.toString());
  });

  return exports.pack(len1, len3, newOps, bankAssem.toString());
};

/**
 * returns a function that tests if a string of attributes
 * (e.g. *3*4) contains a given attribute key,value that
 * is already present in the pool.
 * 返回一个函数，用于测试一个字符串属性如（*3*4）包含一个给定的key，value，已经存在于pool中
 * @param attribPair array [key,value] of the attribute
 * @param pool {AttribPool} Attribute pool
 */
exports.attributeTester = function (attribPair, pool) {
  if (!pool) {
    return never;
  }
  var attribNum = pool.putAttrib(attribPair, true);
  console.log("attributeTester - attribNum : " + JSON.stringify(attribNum));
  if (attribNum < 0) {
    return never;
  } else {
    var re = new RegExp('\\*' + exports.numToString(attribNum) + '(?!\\w)');
    console.log("attributeTester - re : " + JSON.stringify(re));
    return function (attribs) {
      return re.test(attribs);
    };
  }

  function never(attribs) {
    return false;
  }
};

/**
 * creates the identity Changeset of length N
 * @param N {int} length of the identity changeset
 */
exports.identity = function (N) {
  return exports.pack(N, N, "", "");
};


/**
 * creates a Changeset which works on oldFullText and removes text
 * from spliceStart to spliceStart+numRemoved and inserts newText
 * instead. Also gives possibility to add attributes optNewTextAPairs
 * for the new text.
 * 创建一个在oldFullText上工作的变更集，并将文本从spliceStart到spliceStart+ numremove，
 * 插入新文本。还提供了为新文本添加属性optNewTextAPairs的可能性。
 *
 * @param oldFullText {string} old text 老文本
 * @param spliecStart {int} where splicing starts 结合处开始
 * @param numRemoved {int} number of characters to be removed 移除的字符数量
 * @param newText {string} string to be inserted 新的被插入的字符串
 * @param optNewTextAPairs {string} new pairs to be inserted
 * @param pool {AttribPool} Attribution Pool 属性池
 */
exports.makeSplice = function (oldFullText, spliceStart, numRemoved, newText, optNewTextAPairs, pool) {
  var oldLen = oldFullText.length;

  if (spliceStart >= oldLen) {
    spliceStart = oldLen - 1;
  }
  if (numRemoved > oldFullText.length - spliceStart) {
    numRemoved = oldFullText.length - spliceStart;
  }
  var oldText = oldFullText.substring(spliceStart, spliceStart + numRemoved);
  var newLen = oldLen + newText.length - oldText.length;

  // console.log("oldLen : " + oldLen);
  // console.log("spliceStart : " + spliceStart);
  // console.log("numRemoved : " + numRemoved);
  // console.log("oldText : " + oldText);
  // console.log("oldText.length : " + oldText.length);
  // console.log("newText : " + newText);
  // console.log("newLen : " + newLen);
  // console.log("optNewTextAPairs : " + optNewTextAPairs);
  // console.log("pool : " + pool);

  // 封装一个多Op的Changeset
  var assem = exports.smartOpAssembler();
  assem.appendOpWithText('=', oldFullText.substring(0, spliceStart));
  assem.appendOpWithText('-', oldText);
  assem.appendOpWithText('+', newText, optNewTextAPairs, pool);
  assem.endDocument();
  return exports.pack(oldLen, newLen, assem.toString(), newText);
};

/**
 * Transforms a changeset into a list of splices in the form
 * [startChar, endChar, newText] meaning replace text from
 * startChar to endChar with newText
 * @param cs Changeset
 */
exports.toSplices = function (cs) {
  //
  var unpacked = exports.unpack(cs);
  var splices = [];

  var oldPos = 0;
  var iter = exports.opIterator(unpacked.ops);
  var charIter = exports.stringIterator(unpacked.charBank);
  var inSplice = false;
  while (iter.hasNext()) {
    var op = iter.next();
    if (op.opcode == '=') {
      oldPos += op.chars;
      inSplice = false;
    } else {
      if (!inSplice) {
        splices.push([oldPos, oldPos, ""]);
        inSplice = true;
      }
      if (op.opcode == '-') {
        oldPos += op.chars;
        splices[splices.length - 1][1] += op.chars;
      } else if (op.opcode == '+') {
        splices[splices.length - 1][2] += charIter.take(op.chars);
      }
    }
  }

  return splices;
};

/**
 *
 */
exports.characterRangeFollow = function (cs, startChar, endChar, insertionsAfter) {
  var newStartChar = startChar;
  var newEndChar = endChar;
  var splices = exports.toSplices(cs);
  var lengthChangeSoFar = 0;
  for (var i = 0; i < splices.length; i++) {
    var splice = splices[i];
    var spliceStart = splice[0] + lengthChangeSoFar;
    var spliceEnd = splice[1] + lengthChangeSoFar;
    var newTextLength = splice[2].length;
    var thisLengthChange = newTextLength - (spliceEnd - spliceStart);

    if (spliceStart <= newStartChar && spliceEnd >= newEndChar) {
      // splice fully replaces/deletes range
      // (also case that handles insertion at a collapsed selection)
      if (insertionsAfter) {
        newStartChar = newEndChar = spliceStart;
      } else {
        newStartChar = newEndChar = spliceStart + newTextLength;
      }
    } else if (spliceEnd <= newStartChar) {
      // splice is before range
      newStartChar += thisLengthChange;
      newEndChar += thisLengthChange;
    } else if (spliceStart >= newEndChar) {
      // splice is after range
    } else if (spliceStart >= newStartChar && spliceEnd <= newEndChar) {
      // splice is inside range
      newEndChar += thisLengthChange;
    } else if (spliceEnd < newEndChar) {
      // splice overlaps beginning of range
      newStartChar = spliceStart + newTextLength;
      newEndChar += thisLengthChange;
    } else {
      // splice overlaps end of range
      newEndChar = spliceStart;
    }

    lengthChangeSoFar += thisLengthChange;
  }

  return [newStartChar, newEndChar];
};

/**
 * Iterate over attributes in a changeset and move them from
 * oldPool to newPool
 * 迭代所有changset中的属性和移动他们从老的池子到新的池子
 * @param cs {Changeset} Chageset/attribution string to be iterated over
 * @param oldPool {AttribPool} old attributes pool
 * @param newPool {AttribPool} new attributes pool
 * @return {string} the new Changeset
 */
exports.moveOpsToNewPool = function (cs, oldPool, newPool) {
  // works on exports or attribution string
  // 工作在导出或属性字符串
  var dollarPos = cs.indexOf('$');
  if (dollarPos < 0) {
    dollarPos = cs.length;
  }
  var upToDollar = cs.substring(0, dollarPos);
  var fromDollar = cs.substring(dollarPos);
  // order of attribs stays the same
  // 保持属性的顺序一致
  return upToDollar.replace(/\*([0-9a-z]+)/g, function (_, a) {
    var oldNum = exports.parseNum(a);
    var pair = oldPool.getAttrib(oldNum);
    if(!pair) exports.error('Can\'t copy unknown attrib (reference attrib string to non-existant pool entry). Inconsistent attrib state!');
    var newNum = newPool.putAttrib(pair);
    return '*' + exports.numToString(newNum);
  }) + fromDollar;
};

/**
 * create an attribution inserting a text
 * 根据一个插入的文本生成属性
 * @param text {string} text to be inserted
 */
exports.makeAttribution = function (text) {
  var assem = exports.smartOpAssembler();
  assem.appendOpWithText('+', text);
  return assem.toString();
};

/**
 * Iterates over attributes in exports, attribution string, or attribs property of an op
 * and runs function func on them
 * @param cs {Changeset} changeset
 * @param func {function} function to be called
 */
exports.eachAttribNumber = function (cs, func) {
  var dollarPos = cs.indexOf('$');
  if (dollarPos < 0) {
    dollarPos = cs.length;
  }
  var upToDollar = cs.substring(0, dollarPos);

  upToDollar.replace(/\*([0-9a-z]+)/g, function (_, a) {
    func(exports.parseNum(a));
    return '';
  });
};

/**
 * Filter attributes which should remain in a Changeset
 * callable on a exports, attribution string, or attribs property of an op,
 * though it may easily create adjacent ops that can be merged.
 * @param cs {Changeset} changeset to be filtered
 * @param filter {function} fnc which returns true if an
 *        attribute X (int) should be kept in the Changeset
 */
exports.filterAttribNumbers = function (cs, filter) {
  return exports.mapAttribNumbers(cs, filter);
};

/**
 * does exactly the same as exports.filterAttribNumbers
 */
exports.mapAttribNumbers = function (cs, func) {
  var dollarPos = cs.indexOf('$');
  if (dollarPos < 0) {
    dollarPos = cs.length;
  }
  var upToDollar = cs.substring(0, dollarPos);

  var newUpToDollar = upToDollar.replace(/\*([0-9a-z]+)/g, function (s, a) {
    var n = func(exports.parseNum(a));
    if (n === true) {
      return s;
    } else if ((typeof n) === "number") {
      return '*' + exports.numToString(n);
    } else {
      return '';
    }
  });

  return newUpToDollar + cs.substring(dollarPos);
};

/**
 * Create a AText going from Identity to a certain state
 * 创建一个AText对象根据给定的文本和属性
 * @params text {string} text of the final change 最后的变更文本
 * @attribs attribs {string} optional, operations which insert
 *    the text and also puts the right attributes 可选的，插入文本并放入正确属性的操作
 */
exports.makeAText = function (text, attribs) {
  return {
    text: text,
    attribs: (attribs || exports.makeAttribution(text))
  };
};

/**
 * Apply a Changeset to a AText
 * 把一个changeset应用到一个text上
 * @param cs {Changeset} Changeset to be applied
 * @param atext {AText}
 * @param pool {AttribPool} Attribute Pool to add to
 */
exports.applyToAText = function (cs, atext, pool) {
  return {
    text: exports.applyToText(cs, atext.text),
    attribs: exports.applyToAttribution(cs, atext.attribs, pool)
  };
};

/**
 * Clones a AText structure
 * @param atext {AText}
 */
exports.cloneAText = function (atext) {
  if (atext) {
    return {
      text: atext.text,
      attribs: atext.attribs
    }
  } else exports.error("atext is null");
};

/**
 * Copies a AText structure from atext1 to atext2
 * @param atext {AText}
 */
exports.copyAText = function (atext1, atext2) {
  atext2.text = atext1.text;
  atext2.attribs = atext1.attribs;
};

/**
 * Append the set of operations from atext to an assembler
 * @param atext {AText}
 * @param assem Assembler like smartOpAssembler
 */
exports.appendATextToAssembler = function (atext, assem) {
  // intentionally skips last newline char of atext
  var iter = exports.opIterator(atext.attribs);
  var op = exports.newOp();
  while (iter.hasNext()) {
    iter.next(op);
    if (!iter.hasNext()) {
      // last op, exclude final newline
      if (op.lines <= 1) {
        op.lines = 0;
        op.chars--;
        if (op.chars) {
          assem.append(op);
        }
      } else {
        var nextToLastNewlineEnd =
        atext.text.lastIndexOf('\n', atext.text.length - 2) + 1;
        var lastLineLength = atext.text.length - nextToLastNewlineEnd - 1;
        op.lines--;
        op.chars -= (lastLineLength + 1);
        assem.append(op);
        op.lines = 0;
        op.chars = lastLineLength;
        if (op.chars) {
          assem.append(op);
        }
      }
    } else {
      assem.append(op);
    }
  }
};

/**
 * Creates a clone of a Changeset and it's APool
 * @param cs {Changeset}
 * @param pool {AtributePool}
 */
exports.prepareForWire = function (cs, pool) {
  var newPool = new AttributePool();
  var newCs = exports.moveOpsToNewPool(cs, pool, newPool);
  return {
    translated: newCs,
    pool: newPool
  };
};

/**
 * Checks if a changeset s the identity changeset
 */
exports.isIdentity = function (cs) {
  var unpacked = exports.unpack(cs);
  return unpacked.ops == "" && unpacked.oldLen == unpacked.newLen;
};

/**
 * returns all the values of attributes with a certain key
 * in an Op attribs string
 * @param attribs {string} Attribute string of a Op
 * @param key {string} string to be seached for
 * @param pool {AttribPool} attribute pool
 */
exports.opAttributeValue = function (op, key, pool) {
  return exports.attribsAttributeValue(op.attribs, key, pool);
};

/**
 * returns all the values of attributes with a certain key
 * in an attribs string
 * @param attribs {string} Attribute string
 * @param key {string} string to be seached for
 * @param pool {AttribPool} attribute pool
 */
exports.attribsAttributeValue = function (attribs, key, pool) {
  var value = '';
  if (attribs) {
    exports.eachAttribNumber(attribs, function (n) {
      if (pool.getAttribKey(n) == key) {
        value = pool.getAttribValue(n);
      }
    });
  }
  return value;
};

/**
 * Creates a Changeset builder for a string with initial
 * length oldLen. Allows to add/remove parts of it
 * @param oldLen {int} Old length
 */
exports.builder = function (oldLen) {
  var assem = exports.smartOpAssembler();
  var o = exports.newOp();
  var charBank = exports.stringAssembler();

  var self = {
    // attribs are [[key1,value1],[key2,value2],...] or '*0*1...' (no pool needed in latter case)
    keep: function (N, L, attribs, pool) {
      o.opcode = '=';
      o.attribs = (attribs && exports.makeAttribsString('=', attribs, pool)) || '';
      o.chars = N;
      o.lines = (L || 0);
      assem.append(o);
      return self;
    },
    keepText: function (text, attribs, pool) {
      assem.appendOpWithText('=', text, attribs, pool);
      return self;
    },
    insert: function (text, attribs, pool) {
      assem.appendOpWithText('+', text, attribs, pool);
      charBank.append(text);
      return self;
    },
    remove: function (N, L) {
      o.opcode = '-';
      o.attribs = '';
      o.chars = N;
      o.lines = (L || 0);
      assem.append(o);
      return self;
    },
    toString: function () {
      assem.endDocument();
      var newLen = oldLen + assem.getLengthChange();
      return exports.pack(oldLen, newLen, assem.toString(), charBank.toString());
    }
  };

  return self;
};

exports.makeAttribsString = function (opcode, attribs, pool) {
  // makeAttribsString(opcode, '*3') or makeAttribsString(opcode, [['foo','bar']], myPool) work
  if (!attribs) {
    return '';
  } else if ((typeof attribs) == "string") {
    return attribs;
  } else if (pool && attribs && attribs.length) {
    if (attribs.length > 1) {
      console.log("attribs before slice() : " + JSON.stringify(attribs));
      attribs = attribs.slice();
      console.log("attribs after slice() : " + JSON.stringify(attribs));
      attribs.sort();
      console.log("attribs after sort() : " + JSON.stringify(attribs));
    }
    var result = [];
    for (var i = 0; i < attribs.length; i++) {
      var pair = attribs[i];
      console.log("pair : " + JSON.stringify(pair));
      if (opcode == '=' || (opcode == '+' && pair[1])) {
        result.push('*' + exports.numToString(pool.putAttrib(pair)));
      }
    }
    return result.join('');
  }
};

// like "substring" but on a single-line attribution string
exports.subattribution = function (astr, start, optEnd) {
  var iter = exports.opIterator(astr, 0);
  var assem = exports.smartOpAssembler();
  var attOp = exports.newOp();
  var csOp = exports.newOp();
  var opOut = exports.newOp();

  function doCsOp() {
    if (csOp.chars) {
      while (csOp.opcode && (attOp.opcode || iter.hasNext())) {
        if (!attOp.opcode) iter.next(attOp);

        if (csOp.opcode && attOp.opcode && csOp.chars >= attOp.chars && attOp.lines > 0 && csOp.lines <= 0) {
          csOp.lines++;
        }

        exports._slicerZipperFunc(attOp, csOp, opOut, null);
        if (opOut.opcode) {
          assem.append(opOut);
          opOut.opcode = '';
        }
      }
    }
  }

  csOp.opcode = '-';
  csOp.chars = start;

  doCsOp();

  if (optEnd === undefined) {
    if (attOp.opcode) {
      assem.append(attOp);
    }
    while (iter.hasNext()) {
      iter.next(attOp);
      assem.append(attOp);
    }
  } else {
    csOp.opcode = '=';
    csOp.chars = optEnd - start;
    doCsOp();
  }

  return assem.toString();
};

exports.inverse = function (cs, lines, alines, pool) {
  // lines and alines are what the exports is meant to apply to.
  // They may be arrays or objects with .get(i) and .length methods.
  // They include final newlines on lines.

  function lines_get(idx) {
    if (lines.get) {
      return lines.get(idx);
    } else {
      return lines[idx];
    }
  }

  function alines_get(idx) {
    if (alines.get) {
      return alines.get(idx);
    } else {
      return alines[idx];
    }
  }

  var curLine = 0;
  var curChar = 0;
  var curLineOpIter = null;
  var curLineOpIterLine;
  var curLineNextOp = exports.newOp('+');

  var unpacked = exports.unpack(cs);
  var csIter = exports.opIterator(unpacked.ops);
  var builder = exports.builder(unpacked.newLen);

  function consumeAttribRuns(numChars, func /*(len, attribs, endsLine)*/ ) {

    if ((!curLineOpIter) || (curLineOpIterLine != curLine)) {
      // create curLineOpIter and advance it to curChar
      curLineOpIter = exports.opIterator(alines_get(curLine));
      curLineOpIterLine = curLine;
      var indexIntoLine = 0;
      var done = false;
      while (!done && curLineOpIter.hasNext()) {
        curLineOpIter.next(curLineNextOp);
        if (indexIntoLine + curLineNextOp.chars >= curChar) {
          curLineNextOp.chars -= (curChar - indexIntoLine);
          done = true;
        } else {
          indexIntoLine += curLineNextOp.chars;
        }
      }
    }

    while (numChars > 0) {
      if ((!curLineNextOp.chars) && (!curLineOpIter.hasNext())) {
        curLine++;
        curChar = 0;
        curLineOpIterLine = curLine;
        curLineNextOp.chars = 0;
        curLineOpIter = exports.opIterator(alines_get(curLine));
      }
      if (!curLineNextOp.chars) {
        curLineOpIter.next(curLineNextOp);
      }
      var charsToUse = Math.min(numChars, curLineNextOp.chars);
      func(charsToUse, curLineNextOp.attribs, charsToUse == curLineNextOp.chars && curLineNextOp.lines > 0);
      numChars -= charsToUse;
      curLineNextOp.chars -= charsToUse;
      curChar += charsToUse;
    }

    if ((!curLineNextOp.chars) && (!curLineOpIter.hasNext())) {
      curLine++;
      curChar = 0;
    }
  }

  function skip(N, L) {
    if (L) {
      curLine += L;
      curChar = 0;
    } else {
      if (curLineOpIter && curLineOpIterLine == curLine) {
        consumeAttribRuns(N, function () {});
      } else {
        curChar += N;
      }
    }
  }

  function nextText(numChars) {
    var len = 0;
    var assem = exports.stringAssembler();
    var firstString = lines_get(curLine).substring(curChar);
    len += firstString.length;
    assem.append(firstString);

    var lineNum = curLine + 1;
    while (len < numChars) {
      var nextString = lines_get(lineNum);
      len += nextString.length;
      assem.append(nextString);
      lineNum++;
    }

    return assem.toString().substring(0, numChars);
  }

  function cachedStrFunc(func) {
    var cache = {};
    return function (s) {
      if (!cache[s]) {
        cache[s] = func(s);
      }
      return cache[s];
    };
  }

  var attribKeys = [];
  var attribValues = [];
  while (csIter.hasNext()) {
    var csOp = csIter.next();
    if (csOp.opcode == '=') {
      if (csOp.attribs) {
        attribKeys.length = 0;
        attribValues.length = 0;
        exports.eachAttribNumber(csOp.attribs, function (n) {
          attribKeys.push(pool.getAttribKey(n));
          attribValues.push(pool.getAttribValue(n));
        });
        var undoBackToAttribs = cachedStrFunc(function (attribs) {
          var backAttribs = [];
          for (var i = 0; i < attribKeys.length; i++) {
            var appliedKey = attribKeys[i];
            var appliedValue = attribValues[i];
            var oldValue = exports.attribsAttributeValue(attribs, appliedKey, pool);
            if (appliedValue != oldValue) {
              backAttribs.push([appliedKey, oldValue]);
            }
          }
          return exports.makeAttribsString('=', backAttribs, pool);
        });
        consumeAttribRuns(csOp.chars, function (len, attribs, endsLine) {
          builder.keep(len, endsLine ? 1 : 0, undoBackToAttribs(attribs));
        });
      } else {
        skip(csOp.chars, csOp.lines);
        builder.keep(csOp.chars, csOp.lines);
      }
    } else if (csOp.opcode == '+') {
      builder.remove(csOp.chars, csOp.lines);
    } else if (csOp.opcode == '-') {
      var textBank = nextText(csOp.chars);
      var textBankIndex = 0;
      consumeAttribRuns(csOp.chars, function (len, attribs, endsLine) {
        builder.insert(textBank.substr(textBankIndex, len), attribs);
        textBankIndex += len;
      });
    }
  }

  return exports.checkRep(builder.toString());
};

// %CLIENT FILE ENDS HERE%
exports.follow = function (cs1, cs2, reverseInsertOrder, pool) {

  // pool = {"numToAttrib":{"0":["author","a.AVZ0RDPAmWKEfSfD"],"1":["author","a.F3wABRpxZB8PVCGP"]},"attribToNum":{"author,a.AVZ0RDPAmWKEfSfD":0,"author,a.F3wABRpxZB8PVCGP":1},"nextNum":2}

  var unpacked1 = exports.unpack(cs1);
  var unpacked2 = exports.unpack(cs2);
  var len1 = unpacked1.oldLen;
  var len2 = unpacked2.oldLen;
  exports.assert(len1 == len2, "mismatched follow - cannot transform cs1 on top of cs2");
  var chars1 = exports.stringIterator(unpacked1.charBank);
  var chars2 = exports.stringIterator(unpacked2.charBank);

  // 将老长度置为cs1的长度，因为cs1已经执行了，所以长度应该是正确的
  var oldLen = unpacked1.newLen;
  var oldPos = 0;
  var newLen = 0;

  // console.log("Changeset.js - follow - unpacked1 : " + JSON.stringify(unpacked1));
  // unpacked1 = {"oldLen":415,"newLen":416,"ops":"*0+1","charBank":"1"}
  // console.log("Changeset.js - follow - unpacked2 : " + JSON.stringify(unpacked2));
  // unpacked2 = {"oldLen":415,"newLen":416,"ops":"*1+1","charBank":"2"}
  // console.log("Changeset.js - follow - oldLen : " + JSON.stringify(oldLen));
  // oldLen = 416

  // 检查是否包含2个属性，此方法如果没有那两个属性，则返回false
  var hasInsertFirst = exports.attributeTester(['insertorder', 'first'], pool);

  var newOps = exports.applyZip(unpacked1.ops, 0, unpacked2.ops, 0, function (op1, op2, opOut) {
    if (op1.opcode == '+' || op2.opcode == '+') {
      // 如果op1是插入或者op2是插入
      var whichToDo;
      if (op2.opcode != '+') {
        // 如果op2不是插入，则先做op1
        whichToDo = 1;
      } else if (op1.opcode != '+') {
        // 如果op1不是插入，则先做op2
        whichToDo = 2;
      } else {
        // 如果都是op1，op2都是插入
        // both +
        var firstChar1 = chars1.peek(1);
        // console.log("Changeset.js - follow - firstChar1 : " + JSON.stringify(firstChar1));
        // firstChar1 : "1"
        var firstChar2 = chars2.peek(1);
        // console.log("Changeset.js - follow - firstChar2 : " + JSON.stringify(firstChar2));
        // firstChar2 : "2"
        // console.log("Changeset.js - follow - op1.attribs : " + JSON.stringify(op1.attribs));
        // op1.attribs : "*0"
        var insertFirst1 = hasInsertFirst(op1.attribs);
        // console.log("Changeset.js - follow - insertFirst1 : " + JSON.stringify(insertFirst1));
        // insertFirst1 : false
        // console.log("Changeset.js - follow - op2.attribs : " + JSON.stringify(op2.attribs));
        // op2.attribs : "*1"
        var insertFirst2 = hasInsertFirst(op2.attribs);
        // console.log("Changeset.js - follow - insertFirst2 : " + JSON.stringify(insertFirst2));
        // insertFirst2 : false
        if (insertFirst1 && !insertFirst2) {
          // op1包含那两个属性，op2不包含，则做op1
          whichToDo = 1;
        } else if (insertFirst2 && !insertFirst1) {
          // op2包含那两个属性，op1不包含，则做op2
          whichToDo = 2;
        }
        // insert string that doesn't start with a newline first so as not to break up lines
        // 插入的字符串没有以换行符开头，则不用换行
        else if (firstChar1 == '\n' && firstChar2 != '\n') {
          // op1以换行符开头，op2不以换行开头，则做op2
          whichToDo = 2;
        } else if (firstChar1 != '\n' && firstChar2 == '\n') {
          // op2以换行符开头，op1不以换行开头，则做op1
          whichToDo = 1;
        }
        // break symmetry:
        else if (reverseInsertOrder) {
          // 反向插入顺序，则做op2
          whichToDo = 2;
        } else {
          // 其他情况都做op1
          whichToDo = 1;
        }
      }
      if (whichToDo == 1) {
        // 执行op1
        // 跳过op1个字符
        chars1.skip(op1.chars);
        // 将opOut置为保持，保持的数量为op1的行数和op1的字符数
        opOut.opcode = '=';
        opOut.lines = op1.lines;
        opOut.chars = op1.chars;
        opOut.attribs = '';
        // op1置空
        op1.opcode = '';
      } else {
        // 执行op2
        // whichToDo == 2
        // 跳过op2个字符
        // 把op2复制到opOut
        // 将op2置空
        chars2.skip(op2.chars);
        exports.copyOp(op2, opOut);
        op2.opcode = '';
      }
    }
    else if (op1.opcode == '-') {
      if (!op2.opcode) {
        op1.opcode = '';
      } else {
        if (op1.chars <= op2.chars) {
          op2.chars -= op1.chars;
          op2.lines -= op1.lines;
          op1.opcode = '';
          if (!op2.chars) {
            op2.opcode = '';
          }
        } else {
          op1.chars -= op2.chars;
          op1.lines -= op2.lines;
          op2.opcode = '';
        }
      }
    }
    else if (op2.opcode == '-') {
      exports.copyOp(op2, opOut);
      if (!op1.opcode) {
        op2.opcode = '';
      } else if (op2.chars <= op1.chars) {
        // delete part or all of a keep
        op1.chars -= op2.chars;
        op1.lines -= op2.lines;
        op2.opcode = '';
        if (!op1.chars) {
          op1.opcode = '';
        }
      } else {
        // delete all of a keep, and keep going
        opOut.lines = op1.lines;
        opOut.chars = op1.chars;
        op2.lines -= op1.lines;
        op2.chars -= op1.chars;
        op1.opcode = '';
      }
    }
    else if (!op1.opcode) {
      exports.copyOp(op2, opOut);
      op2.opcode = '';
    }
    else if (!op2.opcode) {
      // @NOTE: Critical bugfix for EPL issue #1625. We do not copy op1 here
      // in order to prevent attributes from leaking into result changesets.
      // exports.copyOp(op1, opOut);
      op1.opcode = '';
    }
    else {
      // both keeps
      opOut.opcode = '=';
      opOut.attribs = exports.followAttributes(op1.attribs, op2.attribs, pool);
      if (op1.chars <= op2.chars) {
        opOut.chars = op1.chars;
        opOut.lines = op1.lines;
        op2.chars -= op1.chars;
        op2.lines -= op1.lines;
        op1.opcode = '';
        if (!op2.chars) {
          op2.opcode = '';
        }
      } else {
        opOut.chars = op2.chars;
        opOut.lines = op2.lines;
        op1.chars -= op2.chars;
        op1.lines -= op2.lines;
        op2.opcode = '';
      }
    }


    switch (opOut.opcode) {
    case '=':
      oldPos += opOut.chars;
      newLen += opOut.chars;
      break;
    case '-':
      oldPos += opOut.chars;
      break;
    case '+':
      newLen += opOut.chars;
      break;
    }
  });
  newLen += oldLen - oldPos;

  return exports.pack(oldLen, newLen, newOps, unpacked2.charBank);
};

exports.followAttributes = function (att1, att2, pool) {
  // The merge of two sets of attribute changes to the same text
  // takes the lexically-earlier value if there are two values
  // for the same key.  Otherwise, all key/value changes from
  // both attribute sets are taken.  This operation is the "follow",
  // so a set of changes is produced that can be applied to att1
  // to produce the merged set.
  if ((!att2) || (!pool)) return '';
  if (!att1) return att2;
  var atts = [];
  att2.replace(/\*([0-9a-z]+)/g, function (_, a) {
    atts.push(pool.getAttrib(exports.parseNum(a)));
    return '';
  });
  att1.replace(/\*([0-9a-z]+)/g, function (_, a) {
    var pair1 = pool.getAttrib(exports.parseNum(a));
    for (var i = 0; i < atts.length; i++) {
      var pair2 = atts[i];
      if (pair1[0] == pair2[0]) {
        if (pair1[1] <= pair2[1]) {
          // winner of merge is pair1, delete this attribute
          atts.splice(i, 1);
        }
        break;
      }
    }
    return '';
  });
  // we've only removed attributes, so they're already sorted
  var buf = exports.stringAssembler();
  for (var i = 0; i < atts.length; i++) {
    buf.append('*');
    buf.append(exports.numToString(pool.putAttrib(atts[i])));
  }
  return buf.toString();
};

exports.composeWithDeletions = function (cs1, cs2, pool) {
  var unpacked1 = exports.unpack(cs1);
  var unpacked2 = exports.unpack(cs2);
  var len1 = unpacked1.oldLen;
  var len2 = unpacked1.newLen;
  exports.assert(len2 == unpacked2.oldLen, "mismatched composition of two changesets");
  var len3 = unpacked2.newLen;
  var bankIter1 = exports.stringIterator(unpacked1.charBank);
  var bankIter2 = exports.stringIterator(unpacked2.charBank);
  var bankAssem = exports.stringAssembler();

  var newOps = exports.applyZip(unpacked1.ops, 0, unpacked2.ops, 0, function (op1, op2, opOut) {
    var op1code = op1.opcode;
    var op2code = op2.opcode;
    if (op1code == '+' && op2code == '-') {
      bankIter1.skip(Math.min(op1.chars, op2.chars));
    }
    exports._slicerZipperFuncWithDeletions(op1, op2, opOut, pool);
    if (opOut.opcode == '+') {
      if (op2code == '+') {
        bankAssem.append(bankIter2.take(opOut.chars));
      } else {
        bankAssem.append(bankIter1.take(opOut.chars));
      }
    }
  });

  return exports.pack(len1, len3, newOps, bankAssem.toString());
};

// This function is 95% like _slicerZipperFunc, we just changed two lines to ensure it merges the attribs of deletions properly.
// This is necassary for correct paddiff. But to ensure these changes doesn't affect anything else, we've created a seperate function only used for paddiffs
exports._slicerZipperFuncWithDeletions= function (attOp, csOp, opOut, pool) {
  // attOp is the op from the sequence that is being operated on, either an
  // attribution string or the earlier of two exportss being composed.
  // pool can be null if definitely not needed.
  //print(csOp.toSource()+" "+attOp.toSource()+" "+opOut.toSource());
  if (attOp.opcode == '-') {
    exports.copyOp(attOp, opOut);
    attOp.opcode = '';
  } else if (!attOp.opcode) {
    exports.copyOp(csOp, opOut);
    csOp.opcode = '';
  } else {
    switch (csOp.opcode) {
    case '-':
      {
        if (csOp.chars <= attOp.chars) {
          // delete or delete part
          if (attOp.opcode == '=') {
            opOut.opcode = '-';
            opOut.chars = csOp.chars;
            opOut.lines = csOp.lines;
            opOut.attribs = csOp.attribs; //changed by yammer
          }
          attOp.chars -= csOp.chars;
          attOp.lines -= csOp.lines;
          csOp.opcode = '';
          if (!attOp.chars) {
            attOp.opcode = '';
          }
        } else {
          // delete and keep going
          if (attOp.opcode == '=') {
            opOut.opcode = '-';
            opOut.chars = attOp.chars;
            opOut.lines = attOp.lines;
            opOut.attribs = csOp.attribs; //changed by yammer
          }
          csOp.chars -= attOp.chars;
          csOp.lines -= attOp.lines;
          attOp.opcode = '';
        }
        break;
      }
    case '+':
      {
        // insert
        exports.copyOp(csOp, opOut);
        csOp.opcode = '';
        break;
      }
    case '=':
      {
        if (csOp.chars <= attOp.chars) {
          // keep or keep part
          opOut.opcode = attOp.opcode;
          opOut.chars = csOp.chars;
          opOut.lines = csOp.lines;
          opOut.attribs = exports.composeAttributes(attOp.attribs, csOp.attribs, attOp.opcode == '=', pool);
          csOp.opcode = '';
          attOp.chars -= csOp.chars;
          attOp.lines -= csOp.lines;
          if (!attOp.chars) {
            attOp.opcode = '';
          }
        } else {
          // keep and keep going
          opOut.opcode = attOp.opcode;
          opOut.chars = attOp.chars;
          opOut.lines = attOp.lines;
          opOut.attribs = exports.composeAttributes(attOp.attribs, csOp.attribs, attOp.opcode == '=', pool);
          attOp.opcode = '';
          csOp.chars -= attOp.chars;
          csOp.lines -= attOp.lines;
        }
        break;
      }
    case '':
      {
        exports.copyOp(attOp, opOut);
        attOp.opcode = '';
        break;
      }
    }
  }
};
