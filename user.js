import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyCredential, verifyPresentation } from 'did-jwt-vc'
import { ES256KSigner, decodeJWT, hexToBytes } from 'did-jwt';
import express from 'express';
import cors from 'cors';

//details that the app will check for before allowing VP
const appName = 'my-demo-app';
const userID = 'did:web:ben3101.solidcommunity.net';
const issuerID = 'did:web:issuer123.solidcommunity.net';
//min amount of time to wait between approving request for VP
let timeBetweenVpGrant = 60*60*1000; //ms
console.log('time between grant: '+timeBetweenVpGrant)
//track time last VP was granted to check against policy
let lastVpTimestamp = Math.ceil((Date.now())) - (timeBetweenVpGrant);

//create server to listen to http requests on port 8081
const app = express();
const port = 8081;
//middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded());
app.use((req, res, next)=>{
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('Access-Control-Allow-Methods', 'POST, GET, PATCH, DELETE, OPTIONS');
    next();
});

app.use(express.static('public'));

app.post('/vprequest', async (req, res) => {
    console.log("Received VP Request at "+(Date.now()));
    const {user, vcissuer, application, nonce, domain} = req.body;
    console.log(`\nuser: ${user}\nissuer: ${vcissuer}\napp: ${application}\nnonce: ${nonce}\ndomain: ${domain}\n`);
    //check if VP can be made for the given details, and at this time. 
    if((application === appName && user === userID && vcissuer === issuerID)){
      if((Math.ceil((Date.now())) > (lastVpTimestamp + timeBetweenVpGrant))){
        console.log(`Comparing last issue (${lastVpTimestamp}) with current time (${Date.now()})...`);
        console.log("Creating VC...");
        const VC = await createVC(vcissuer, user);
        console.log("\nCreating VP...");
        const VP = await createVP(VC, nonce, domain, user, application);
        console.log("VP (JWT):\n"+JSON.stringify(VP));
        console.log("\nSending VP back to app...");
        lastVpTimestamp = Math.ceil((Date.now()));
        res.status(200).send(VP);
      }else{
        res.status(403).send(`A VP can only be sent every ${timeBetweenVpGrant/1000} seconds and the last was sent ${(Date.now()-lastVpTimestamp)/1000} seconds ago. Try again later.`)
      }
        
    }else{
        res.status(401).send('Unable to create a VP with those details.')
    }
});

app.listen(port, () => {
    console.log(`Server Established on Port ${port}\n`);
})

//VC/VP code----------------------------
async function createVC(issuer, user){
    // Create a signer by using a private key (hex).
  //ben3101 key
  //const VcIssuerKey = 'a17cb543a7fbf5493a9754c977826925a346964c5b292e9da31bb6940f698313';
  //issuer123 key
  const VcIssuerKey = '2143c4bd995378ce36bacfcfda2e39610f2809e349b4d25e7b7d2b5f1d82e6ae';
  const VcSigner = ES256KSigner(hexToBytes(VcIssuerKey))

  // Prepare an issuer (of VC)
  const vcIssuer = {
      did: issuer,
      signer: VcSigner
  }

  //Create a VC:
  //use today's date for issuance
  let today = Math.ceil((Date.now() / 1000));
  let tenYearsFromNow = today + 315569260;

  //test dates for expired VC, make issuance 10 years ago and expiry yesterday
  // tenYearsFromNow = today - 86400;
  // today = today - 315569260;
  //-payload
  const vcPayload = {
    sub: user,
    //nbf: 1562950282,
    nbf: today,
    exp: tenYearsFromNow,
    vc: {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      type: ["VerifiableCredential", "UniversityDegreeCredential"],
      credentialSubject: {
        degree: {
          type: "BachelorDegree",
          name: "Bachelor of Science"
        }
      }
    }
  }
  //console.log("VC payload:\n"+JSON.stringify(vcPayload));
  //-convert VC to JWT
  const vcJwt = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
  return vcJwt;
}
async function createVP(vc, nonce, domain, user, appName){
  //Create a VP:
  //the VC holder will sign the VP
  //ben3101 key
  const VpSignerKey = 'a17cb543a7fbf5493a9754c977826925a346964c5b292e9da31bb6940f698313';
  //issuer123 key
  //const VpSignerKey = '2143c4bd995378ce36bacfcfda2e39610f2809e349b4d25e7b7d2b5f1d82e6ae';
  const VpSigner = ES256KSigner(hexToBytes(VpSignerKey))
  const holder = {
    did: user,
    signer: VpSigner
}

  //-VP payload
  //set expiry time
  let today = Math.ceil((Date.now() / 1000));
  let fiveMinsFromNow = today + (5*60*1000);
  const vpPayload = {
    vp: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      verifiableCredential: [vc],
      nonce: nonce,
      domain: domain,
      appName: appName,
    },
    exp: fiveMinsFromNow
  }
  //console.log("VP payload:\n"+JSON.stringify(vpPayload));
  const vpJwt = await createVerifiablePresentationJwt(vpPayload, holder);
  return vpJwt;
}
