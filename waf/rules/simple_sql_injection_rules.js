module.exports = {
    sqlInjection_rules: [
        'union\\s*?\\s*?[([]*?\\s*?select\\s+',
        'union\\s*?all\\s*?[([]*?\\s*?select\\s+',
        'union\\s*?distinct\\s*?[([]*?\\s*?select\\s+',
        'union\\s*?[(!@]*?\\s*?[([]*?\\s*?select\\s+'
    ]
};
