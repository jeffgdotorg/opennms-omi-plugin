grammar OMiPatternMatch;

pattern
        : '"' patternBody '"' ICASE?
        ;
patternBody
        : CARAT? unit* DOLLAR?
        ;
unit
        : literal (PIPE literal)*?
        | squareBracketGrouping
        | angleBracketExpr
        ;
literal
        : (.)*?
        ;
squareBracketGrouping
        : '[' unit ']'
        ;
angleBracketExpr
        : '<' angleBracketExprBody userVarAssignment? '>'
        ;
angleBracketExprBody
        : angleBracketGlob
        | unit
        ;
angleBracketGlob
        : GLOB_QUANTIFIER? GLOB_CHARACTER
        ;
GLOB_QUANTIFIER
        : '1'..'9' ('0'..'9')*
        ;
GLOB_CHARACTER
        : (GLOB_STAR|GLOB_HASH|GLOB_UNDERSCORE|GLOB_AT|GLOB_SLASH|GLOB_S)
        ;
userVarAssignment
        : '.' userVarName
        ;
userVarName
        : ('a'..'z'|'A'..'Z'|'0'..'9'|'_')*
        ;
CARAT
        : '^'
        ;
DOLLAR
        : '$'
        ;
PIPE
        : '|'
        ;
ICASE
        : 'ICASE'
        ;
GLOB_STAR
        : '*'
        ;
GLOB_HASH
        : '#'
        ;
GLOB_UNDERSCORE
        : '_'
        ;
GLOB_AT
        : '@'
        ;
GLOB_SLASH
        : '/'
        ;
GLOB_S
        : 'S'
        ;