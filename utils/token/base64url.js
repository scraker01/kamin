export const encode = (text) => {
    // const {text} = req.body;

    const result = Buffer.from(text).
                toString('base64').
                replace(/\+/g,'-').
                replace(/\//g, '"').
                replace(/\//g, "").
                replace(/\=/g, "")

    return result;
}

export const decode = (encodedText) => {
    

    const base64 = encodedText
        .replace(/-/g, '+')
        .replace(/"/g, '/')
        .padEnd(Math.ceil(encodedText.length / 4) * 4, '=');

    // Decode the Base64 string
    const result = Buffer.from(base64, 'base64').toString('utf-8');

    return result;

}