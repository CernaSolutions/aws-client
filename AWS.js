gs.include('HMAC256');

var AWS = {
    /**
     * Does nothing for now
     */
    initialize: function() {},

    /**
     * Enables or disables debug logging
     * @type {Boolean}
     */
    debug: false,

    /**
     * AWS Access and Secret Keys
     * These can be retrieved from the AWS Dashboard under My Security Credentials
     * Access keys for CLI, SDK, & API access
     */
    access_key: gs.getProperty('aws.access_key'),
    secret_key: gs.getProperty('aws.secret_key'),

    /**
     * Contains the AWS Comprehend Functions
     * @type {Object}
     */
    Comprehend: {

        /**
         * Returns a sentiment analysis for given text from AWS
         * @param {String} text The text to analyze
         */
        DetectSentiment: function(text) {
            return AWS.executeRequest({
                method: 'POST',
                service: 'comprehend',
                host: 'comprehend.us-east-2.amazonaws.com',
                region: 'us-east-2',
                endpoint: 'https://comprehend.us-east-2.amazonaws.com/',
                content_type: 'application/x-amz-json-1.1',
                amz_target: 'Comprehend_20171127.DetectSentiment',
                request_parameters: [
                    '{',
                    '"LanguageCode": "en",',
                    '"Text": "' + text + '"',
                    '}'
                ].join('')
            });
        }
    },

    /**
     * Executes the given AWS API Request
     * @param  {Object} apiRequest An object containing properties for the API Request
     * @return {Object}            AWS Response object
     */
    executeRequest: function(apiRequest) {
        var authorizationHeader = this.createAuthorizationHeader(apiRequest);
        var request = new sn_ws.RESTMessageV2();

        request.setEndpoint(apiRequest.endpoint);
        request.setHttpMethod(apiRequest.method);
        request.setRequestBody(apiRequest.request_parameters);
        request.setRequestHeader('Content-Type', apiRequest.content_type);
        request.setRequestHeader('X-Amz-Date', authorizationHeader.amz_date);
        request.setRequestHeader('X-Amz-Target', apiRequest.amz_target);
        request.setRequestHeader('Authorization', authorizationHeader.authorization_header);

        if (this.debug) {
            gs.info('-- Executing Request ----------------')
            gs.info('Endpoint: ' + apiRequest.endpoint)
            gs.info('Request Body: ');
            gs.info(apiRequest.request_parameters)
            gs.info('Content-Type: ' + apiRequest.content_type);
            gs.info('X-Amz-Date: ' + authorizationHeader.amz_date);
            gs.info('X-Amz-Target: ' + apiRequest.amz_target);
            gs.info('Authorization: ' + authorizationHeader.authorization_header);
        }

        var response = request.execute();
        var httpResponseStatus = response.getStatusCode();

        if (this.debug) {
            gs.info('-- Response -------------------------');
            gs.info('Response code: ' + response.getStatusCode());
            gs.info('Response body:');
            gs.info(response.getBody());
        }

        if (httpResponseStatus != '200') {
            gs.info("AWS Error: " + response.getBody());
            return false;
        } else {
            return JSON.parse(response.getBody());
        }
    },

    /**
     * Creates the SIG4 Request Auth Headers for the given API Request
     * @param  {Object} apiRequest An object containing properties for the API Request
     * @return {Object}            An object containing the date stamp and authorization header
     */
    createAuthorizationHeader: function(apiRequest) {
        var dateTimeNow = new GlideDateTime();
        var amz_date = dateTimeNow.getValue().split(' ').join('T').split('-').join('').split(':').join('') + 'Z';
        var date_stamp = dateTimeNow.getValue().split(' ')[0].split('-').join('').split(':').join('');

        var canonical_uri = '/';
        var canonical_querystring = '';
        var canonical_headers =
            'content-type:' + apiRequest.content_type + '\n' +
            'host:' + apiRequest.host + '\n' +
            'x-amz-date:' + amz_date + '\n' +
            'x-amz-target:' + apiRequest.amz_target + '\n';

        var signed_headers = 'content-type;host;x-amz-date;x-amz-target';
        var payload_hash = this.sha256(apiRequest.request_parameters);
        var canonical_request =
            apiRequest.method + '\n' +
            canonical_uri + '\n' +
            canonical_querystring + '\n' +
            canonical_headers + '\n' +
            signed_headers + '\n' +
            payload_hash;

        var algorithm = 'AWS4-HMAC-SHA256'
        var credential_scope = date_stamp + '/' + apiRequest.region + '/' + apiRequest.service + '/' + 'aws4_request'
        var string_to_sign =
            algorithm + '\n' +
            amz_date + '\n' +
            credential_scope + '\n' +
            this.sha256(canonical_request);

        var signing_key = this.getSignatureKey(this.secret_key, date_stamp, apiRequest.region, apiRequest.service)
        var signature = this.sign(signing_key, string_to_sign);
        var authorization_header = algorithm + ' ' + 'Credential=' + this.access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature;

        return {
            amz_date: amz_date,
            authorization_header: authorization_header
        };
    },

    /**
     * Creates a Message Authentication Code 
     * @param  {String} key Plaintext key to encode with
     * @param  {String} msg The message to encode
     * @return {String}     The encoded message
     */
    sign: function(key, msg) {
        var mac = CryptoJS.HmacSHA256(msg, key);
        if (this.debug) {
            gs.info(mac);
        }

        return mac;
    },

    /**
     * Gets an AWS signature key by signing the given inputs
     * @param  {String} key         The AWS Secret Key
     * @param  {String} dateStamp   Date of the request in YYYYMMDD format
     * @param  {String} regionName  AWS Region of the request
     * @param  {String} serviceName Name of the AWS Service
     * @return {String}             Signature Key string
     */
    getSignatureKey: function(key, dateStamp, regionName, serviceName) {
        var kDate = this.sign('AWS4' + key, dateStamp);
        var kRegion = this.sign(kDate, regionName);
        var kService = this.sign(kRegion, serviceName);
        var kSigning = this.sign(kService, 'aws4_request');
        return kSigning;
    },

    /**
     * Returns the SHA256 has of a given ASCII string
     * https://geraintluff.github.io/sha256/
     * 
     * @param  {String} ascii The plain text to hash
     * @return {String}       SHA256 for the plain text
     */
    sha256: function(ascii) {
        function rightRotate(value, amount) {
            return (value >>> amount) | (value << (32 - amount));
        };

        var mathPow = Math.pow;
        var maxWord = mathPow(2, 32);
        var lengthProperty = 'length'
        var i, j; // Used as a counter across the whole file
        var result = ''

        var words = [];
        var asciiBitLength = ascii[lengthProperty] * 8;

        //* caching results is optional - remove/add slash from front of this line to toggle
        // Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
        // (we actually calculate the first 64, but extra values are just ignored)
        var hash = this.sha256.h = this.sha256.h || [];
        // Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
        var k = this.sha256.k = this.sha256.k || [];
        var primeCounter = k[lengthProperty];
        /*/
        var hash = [], k = [];
        var primeCounter = 0;
        //*/

        var isComposite = {};
        for (var candidate = 2; primeCounter < 64; candidate++) {
            if (!isComposite[candidate]) {
                for (i = 0; i < 313; i += candidate) {
                    isComposite[i] = candidate;
                }
                hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
                k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
            }
        }

        ascii += '\x80' // Append Ƈ' bit (plus zero padding)
        while (ascii[lengthProperty] % 64 - 56) ascii += '\x00' // More zero padding
        for (i = 0; i < ascii[lengthProperty]; i++) {
            j = ascii.charCodeAt(i);
            if (j >> 8) return; // ASCII check: only accept characters in range 0-255
            words[i >> 2] |= j << ((3 - i) % 4) * 8;
        }
        words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
        words[words[lengthProperty]] = (asciiBitLength)

        // process each chunk
        for (j = 0; j < words[lengthProperty];) {
            var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
            var oldHash = hash;
            // This is now the undefinedworking hash", often labelled as variables a...g
            // (we have to truncate as well, otherwise extra entries at the end accumulate
            hash = hash.slice(0, 8);

            for (i = 0; i < 64; i++) {
                var i2 = i + j;
                // Expand the message into 64 words
                // Used below if 
                var w15 = w[i - 15],
                    w2 = w[i - 2];

                // Iterate
                var a = hash[0],
                    e = hash[4];
                var temp1 = hash[7] +
                    (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
                    +
                    ((e & hash[5]) ^ ((~e) & hash[6])) // ch
                    +
                    k[i]
                    // Expand the message schedule if needed
                    +
                    (w[i] = (i < 16) ? w[i] : (
                        w[i - 16] +
                        (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) // s0
                        +
                        w[i - 7] +
                        (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10)) // s1
                    ) | 0);
                // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
                var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
                    +
                    ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2])); // maj

                hash = [(temp1 + temp2) | 0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
                hash[4] = (hash[4] + temp1) | 0;
            }

            for (i = 0; i < 8; i++) {
                hash[i] = (hash[i] + oldHash[i]) | 0;
            }
        }

        for (i = 0; i < 8; i++) {
            for (j = 3; j + 1; j--) {
                var b = (hash[i] >> (j * 8)) & 255;
                result += ((b < 16) ? 0 : '') + b.toString(16);
            }
        }
        return result;
    },

    type: 'AWS'
};