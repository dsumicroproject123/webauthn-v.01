async function post(endpoint, params) {
    return fetch(endpoint, {
        credentials: 'include',
        body: params,
        method: 'POST',
    });
}
function base64encode(src) {
    let buffer = (src instanceof ArrayBuffer) ? src : src.buffer;
    return btoa(
        Array.from(new Uint8Array(buffer)).map(
            x => String.fromCodePoint(x)).join('')
    );
}

function base64decode(s) {
    return new Uint8Array(Array.from(atob(s)).map(x => x.charCodeAt(0)));
}

function setStatus(s) {
    let statusElement = document.getElementById('status');
    statusElement.innerText = s;
}
function parseCreationOptions(opts) {
    let pOpts = Object.assign({}, opts);
    if ('challenge' in pOpts.publicKey) {
        pOpts.publicKey.challenge = base64decode(opts.publicKey.challenge);
    }

    if ('user' in pOpts.publicKey && 'id' in pOpts.publicKey.user) {
        pOpts.publicKey.user.id = base64decode(opts.publicKey.user.id);
    }

    return pOpts;
}


async function registerUsername() {
    let params = new URLSearchParams();
    let username = document.getElementById('username').value;
    params.append('username', username);
    setStatus('Registering username ' + username + '.');
    let response = await post('/registration/request/', params);
    if (!response.ok) {
        setStatus('Failed to register username...could already be registered.');
        throw Error;
    }

    registrationRequest = await response.json();
    cco = parseCreationOptions(registrationRequest.creationOptions);
    registeredUsername = username;
    setStatus('Creating credential for ' + username + '.');
    attestation = await navigator.credentials.create(cco);
}

function attestationJSON(cred) {
    let credJSON = {};
    credJSON.type = cred.type;
    credJSON.id = cred.id;
    credJSON.rawId = base64encode(cred.rawId);
    credJSON.response = {
        attestationObject: base64encode(cred.response.attestationObject),
        clientDataJSON: base64encode(cred.response.clientDataJSON),
    };
    return credJSON;
}


async function registerAttestation() {
    setStatus('Attesting credential for ' + registeredUsername + '.');
    let attJSON = attestationJSON(attestation);
    let params = new URLSearchParams();
    params.append('challengeID', registrationRequest.challengeID);
    params.append('credential', JSON.stringify(attJSON));
    params.append('username', registeredUsername);
    let response = await post('/registration/response/', params);
    if (response.ok) {
        setStatus(
            'Successfully registered credential for ' + registeredUsername + '!');
    } else {
        setStatus(
            'Failed to register credential for ' + registeredUsername + '...');
    }
}
async function register() {
    await registerUsername();
    await registerAttestation();
}
function parseRequestOptions(opts) {
    let pOpts = Object.assign({}, opts);
    if ('challenge' in pOpts.publicKey) {
        pOpts.publicKey.challenge = base64decode(opts.publicKey.challenge);
    }

    if ('allowCredentials' in pOpts.publicKey) {
        let allowCredentials = [];
        for (let i = 0; i < pOpts.publicKey.allowCredentials.length; i++) {
            let nCred = Object.assign({}, pOpts.publicKey.allowCredentials[i]);
            nCred.id = base64decode(opts.publicKey.allowCredentials[i].id);
            allowCredentials.push(nCred);
        }

        pOpts.publicKey.allowCredentials = allowCredentials;
    }

    return pOpts;
}


async function requestAuthentication() {
    let params = new URLSearchParams();
    let username = document.getElementById('username').value;
    params.append('username', username);
    setStatus('Requesting authentication for username ' + username + '.');
    let response = await post('/authentication/request/', params);
    if (!response.ok) {
        setStatus('Failed to request authentication...');
        throw Error;
    }

    authenticationRequest = await response.json();
    cro = parseRequestOptions(authenticationRequest.requestOptions);
    authenticatingUsername = username;
    assertion = await navigator.credentials.get(cro);
}
function assertionJSON(cred) {
    let credJSON = {};
    credJSON.type = cred.type;
    credJSON.id = cred.id;
    credJSON.rawId = base64encode(cred.rawId);
    credJSON.response = {
        authenticatorData: base64encode(cred.response.authenticatorData),
        clientDataJSON: base64encode(cred.response.clientDataJSON),
        signature: base64encode(cred.response.signature),
    }

    if ('userHandle' in cred.response && cred.response.userHandle != null) {
        if (cred.response.userHandle.byteLength > 0) {
            credJSON.response.userHandle = base64encode(cred.response.userHandle);
        }
    }

    return credJSON;

    async function assertAuthentication() {
        setStatus('Asserting credential for ' + authenticatingUsername);
        let aJSON = assertionJSON(assertion);
        let params = new URLSearchParams();
        params.append('challengeID', authenticationRequest.challengeID);
        params.append('credential', JSON.stringify(aJSON));
        params.append('username', authenticatingUsername);
        let response = await post('/authentication/response/', params);
        if (response.ok) {
            setStatus(
                'Successfully authorized username ' + authenticatingUsername + '!');
        } else {
            setStatus(
                'Failed to authorize username ' + authenticatingUsername + '...');
        }
    }

    async function authenticate(){
        await requestAuthentication();
        await assertAuthentication();
    }}
