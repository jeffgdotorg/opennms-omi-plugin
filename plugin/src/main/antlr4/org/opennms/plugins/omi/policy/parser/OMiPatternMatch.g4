grammar OMiPatternMatch;

pattern
        : '"' patternBody '"' 'ICASE'?
        ;
patternBody
        : '^'? unit '$'?
        ;
unit
        : (.)* 
        ;

WS
        : [\t\r\n]+ -> skip
        ;