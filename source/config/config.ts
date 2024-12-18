import dotenv from 'dotenv';

dotenv.config();

const MYSQL_HOST = process.env.MYSQL_HOST || "DATABASE_HOST_NAME";
const MYSQL_DATABASE = process.env.MYSQL_DATABASE || "YOUR_DATABASE_NAME";
const MYSQL_USER = process.env.MYSQL_USER || "DATABASE_USERNAME";
const MYSQL_PASSWORD = process.env.MYSQL_PASSWORD || "DATABASE_PASSWORD";


const MYSQL = {
    host: MYSQL_HOST,
    database: MYSQL_DATABASE,
    user: MYSQL_USER,
    password: MYSQL_PASSWORD
};

const SERVER_HOSTNAME = process.env.SERVER_HOSTNAME || 'localhost';
const SERVER_PORT = process.env.SERVER_PORT || 8080
const SERVER_TOKEN_EXPIRETIME = process.env.SERVER_TOKEN_EXPIRETIME || 3600;
const SERVER_REFRESH_TOKEN_EXPIRETIME = process.env.SERVER_REFRESH_TOKEN_EXPIRETIME || 86400;
//For Testing
// const SERVER_TOKEN_EXPIRETIME = process.env.SERVER_TOKEN_EXPIRETIME || 60; //3600
// const SERVER_REFRESH_TOKEN_EXPIRETIME = process.env.SERVER_REFRESH_TOKEN_EXPIRETIME || 300; //86400
const SERVER_TOKEN_ISSUER = process.env.SERVER_TOKEN_ISSUER || 'coolIssuer';
const SERVER_TOKEN_SECRET = process.env.SERVER_TOKEN_SECRET || 'superencryptedsecret';

const SERVER = {
    hostname: SERVER_HOSTNAME,
    port: SERVER_PORT,
    token: {
        expireTime: SERVER_TOKEN_EXPIRETIME,
        issuer: SERVER_TOKEN_ISSUER,
        secret: SERVER_TOKEN_SECRET,
        refreshExpirationTime: SERVER_REFRESH_TOKEN_EXPIRETIME,
    }
};

const BASEREQUST = [
    '/api/app/users/login',
    '/api/app/users/signUp',
    '/api/app/users/checkContactNoExist',
    '/api/app/users/registerViaPhone',
    '/api/app/home/getLatestProfile',
    '/api/app/users/getNearestApplicant',
    '/api/app/users/getMostViewedApplicant',
    '/api/app/users/viewUserDetail',
    '/api/app/users/searchUser',
    '/api/app/users/getMasterData',
    '/api/admin/systemflags/getAdminSystemFlag',
    '/api/app/questioncategories/getQuestion',
    '/api/app/package/getpackage',
    '/api/app/regions/getStates',
    '/api/app/regions/getDistricts',
    '/api/app/regions/getCities',
    '/api/app/regions/getCountries',
    // '/api/app/regions/getRegionByPincode',
    '/api/app/successStories/getSuccessStories'
];

// 
 const fromEmail = process.env.FROM_EMAIL || "admin@native.software";
const EMAILMATRIMONYSETPASSWORD = {
    fromName: "Indiaviah Team",
    fromEmail: fromEmail,
    subject: "link to reset password",
    html: '<span>Hi [NAME],</span> <br/><br/> <p>Below is the link to verify your account and new Password of your login</p>\
    <br/><br/> <span style="font-weight:bolder; font-size:x-large; color:grey"><a href ="https://matrimonyadmin.native.software/reset-password/[VERIFICATION_TOKEN]">Click to Verify</a></span><br>  <span>Thank You, <br> Native Software Team</span>'
};

const EMAILMATRIMONYNEWUSERREGISTER = {
    fromName: "Indiaviah Team",
    fromEmail: fromEmail,
    subject: "New User Registration Notification",
    html: `
    Dear Admin,<br/><br/>
    I hope this message finds you well. I wanted to inform you that a new user has successfully registered in our system. Below are the details of the new user:
<br/>
    Name: [User's Full Name]<br/><br/>
    Contact No: [User's Contact No]<br/><br/>
    Email: [User's Email Address]<br/><br/>
    Please review the information and ensure that the new user's account is appropriately set up. If any further action is required on your part, or if you have any specific onboarding procedures for new users, kindly proceed accordingly.
<br/><br/>
    If you have any questions or need additional details, feel free to reach out to me or the support team.
<br/><br/>
    Thank you for your attention to this matter.
<br/><br/>
    Best regards,
<br/><br/>
    Indiaviah Team`
};

const EMAILMATRIMONYTWOFACTORAUTHENTICATION = {
    fromName: "Indiaviah Team",
    fromEmail: fromEmail,
    subject: "New User Registration Notification",
    html: `
    Hey [FullName],<br/><br/>
    A sign in attempt requires further verification. To complete the sign in, enter the below verification code  
<br/><br/>
    Verification code: [VerificationCode]
<br/><br/>
    If you did not attempt to sign in to your account, your password may be compromised
<br/><br/>
    Thanks,
<br/><br/>
    Native Software Team`
};

// const KEY_ID = process.env.KEY_ID || 'rzp_test_QsDMPb9jLx9EbE';
// const SECRET_KEY = process.env.SECRET_KEY || 'mZk44Ei1HtdmkqE3KxlMC5zz';

// const KEY = {
//     keyId: KEY_ID,
//     secretKey: SECRET_KEY
// }

const APP_ID = process.env.APP_ID || '32cc47360e134c6fa4c2a683f0fc5425';
const APP_CERTIFICATE = process.env.APP_CERTIFICATE || '817c8f56e7da4f748208f4804a503f9f';

const AGORA = {
    appId: APP_ID,
    appCertificate: APP_CERTIFICATE
}

const config = {
    mysql: MYSQL,
    server: SERVER,
    baseRequests: BASEREQUST,
    emailMatrimonySetPassword: EMAILMATRIMONYSETPASSWORD,
    emailMatrimonyNewUserRegister: EMAILMATRIMONYNEWUSERREGISTER,
    emailMatrimonyTwoFactorAuthentication: EMAILMATRIMONYTWOFACTORAUTHENTICATION,
    // key:KEY
    // key:KEY,
    agora: AGORA
};

export default config;


// <rewrite>
// <rules>
//     <rule name="nodejs" >
//         <match url="(.*)" >
//         <conditions>
//             <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
//         </conditions>
//         <action type="Rewrite" url="build/server.js" />
//     </rule>
// </rules>
// </rewrite>