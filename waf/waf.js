var lowerCase = require('lower-case');
var sqlInjection_rules = require("./waf/rules/simple_sql_injection_rules").sqlInjection_rules;
const Entities = require('html-entities').AllHtmlEntities;

const noProcessor = 0;
const urlDecodeProcessor = 1;
const urlDoubleDecodeProcessor = 2;
const tripleUrlDecodeProcessor = 3;
const htmlDecodeprocessor = 4;


function processors(data, processor_id) {

    data = lowerCase(data);

    // no processor
    if (processor_id == noProcessor) {
        return data
    }

    // url decode
    if (processor_id == urlDecodeProcessor) {
        return decodeURIComponent(data);
    }

    // double url decode
    if (processor_id == urlDoubleDecodeProcessor) {
        return decodeURIComponent(decodeURIComponent(data));
    }

    // triple url decode
    if (processor_id == tripleUrlDecodeProcessor) {
        return decodeURIComponent(decodeURIComponent(data));
    }

    // html decode
    if (processor_id == htmlDecodeprocessor) {
        return new Entities().decode(data);
    }

    // sqlmap tampers will be add
    // 0x2char
    // apostrophemask
    // apostrophenull
    // appendnullbyte
    // base64
    // bluecoat
    // chardouble
    // charunicode
    // charunicodeescape
    // escapequotes
    // halfversionedmorekeywords
    // luanginx
    // modsecurityversioned
    // modsecurityzeroversioned
    // multiplespaces
    // overlongutf8
    // overlongutf8more
    // percentage
    // randomcase
    // randomcomments
    // space2comment
    // space2dash
    // space2hash
    // space2morecomment
    // space2morehash
    // space2mssqlblank
    // space2mssqlhash
    // space2mysqlblank
    // space2mysqldash
    // space2plus
    // space2randomblank
    // symboliclogical
    // unmagicquotes
    // versionedkeywords
    // versionedmorekeywords


    throw new Error("processor not found " + processor_id);
}

module.exports = {
    wafCheckToBlock: function (event) {
        const theRequest = event.Records[0].request;
        const uri = req.uri;
        for (var i = 0; i < sqlInjection_rules.length; i++) {
            if (
                processors(uri, noProcessor).search(sqlInjection_rules[i]) != -1 ||
                processors(uri, urlDecodeProcessor).search(sqlInjection_rules[i]) != -1 ||
                processors(uri, urlDoubleDecodeProcessor).search(sqlInjection_rules[i]) != -1 ||
                processors(uri, tripleUrlDecodeProcessor).search(sqlInjection_rules[i]) != -1 ||
                processors(uri, htmlDecodeprocessor).search(sqlInjection_rules[i]) != -1
            ) {
                return true;
            }
        }
        return false;
    }
}
