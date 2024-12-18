import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

// const mysql = require('mysql');
// const util = require('util');

// let connection = mysql.createConnection({
//     host: config.mysql.host,
//     user: config.mysql.user,
//     password: config.mysql.password,
//     database: config.mysql.database
// });

// const query = util.promisify(connection.query).bind(connection);

const NAMESPACE = 'Visitors';

const getVisitors = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Visitors');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null
            // let newSql = `select  up.id , up.userId  as visitorId, up.status, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl as image, o.name as occupation, upd.birthDate, 
            // addr.cityName, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upd.birthDate)), '%Y') + 0 AS age FROM userproposals up 
            // LEFT JOIN users u ON u.id = up.proposalUserId
            // LEFT JOIN images img ON img.id = u.imageId
            // LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
            // LEFT JOIN occupation o ON o.id = upd.occupationId where up.userId = ` + userId + ` AND `

            let countSql = `select COUNT(*) as totalCount from (SELECT up.id , up.proposalUserId  as visitorId, up.status, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl as image, o.name as occupation, upd.birthDate, 
                addr.cityName, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upd.birthDate)), '%Y') + 0 AS age, 
                up.proposalUserId IN (select userBlockId from userblock where userId =` + userId + `)  as isBlockByMe , 
                                up.proposalUserId IN (select userId from userblock where userBlockId =` + userId + `)  as isBlockByOther,
                                u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
                                u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
                                 FROM userproposals up 
                                 LEFT JOIN users u ON u.id = up.proposalUserId
                                 LEFT JOIN images img ON img.id = u.imageId
                                 LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                 LEFT JOIN occupation o ON o.id = upd.occupationId
                                 LEFT JOIN addresses addr ON addr.id = upd.addressId WHERE up.userId =` + userId + ` 
                                 and u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)   
                                 and u.id NOT IN (select userId from userblock where userBlockId =` + userId + `)
                                 and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
                                 union 
                                 SELECT up.id , up.userId  as visitorId, up.status, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl as image, o.name as occupation, upd.birthDate, 
                                 addr.cityName, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upd.birthDate)), '%Y') + 0 AS age,
                                 up.proposalUserId IN (select userBlockId from userblock where userId = ` + userId + `)  as isBlockByMe , 
                                up.proposalUserId IN (select userId from userblock where userBlockId = ` + userId + `)  as isBlockByOther,
                                u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
                                u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
                                 FROM userproposals up 
                                 LEFT JOIN users u ON u.id = up.userId
                                 LEFT JOIN images img ON img.id = u.imageId
                                 LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                 LEFT JOIN occupation o ON o.id = upd.occupationId
                                 LEFT JOIN addresses addr ON addr.id = upd.addressId WHERE up.proposalUserId = ` + userId + ` 
                                 and u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)  
                                 and u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                                 and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `))  as t1 WHERE t1.status = true`
            let countResult = await header.query(countSql)

            let sql = `select * from (SELECT u.id , up.proposalUserId  as visitorId, up.status, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl as image, o.name as occupation
                , upd.birthDate, upd.eyeColor, upd.languages, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId , pf.name as profileForName
                , addr.cityName, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upd.birthDate)), '%Y') + 0 AS age 
                , up.proposalUserId IN (select userBlockId from userblock where userId =` + userId + `)  as isBlockByMe , 
                                up.proposalUserId IN (select userId from userblock where userBlockId =` + userId + `)  as isBlockByOther,
                                u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
                                u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
                                 FROM userproposals up 
                                 LEFT JOIN users u ON u.id = up.proposalUserId
                                 LEFT JOIN images img ON img.id = u.imageId
                                 LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                 LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 LEFT JOIN occupation o ON o.id = upd.occupationId
                                 LEFT JOIN addresses addr ON addr.id = upd.addressId WHERE up.userId =` + userId + ` 
                                 and u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)   
                                 and u.id NOT IN (select userId from userblock where userBlockId =` + userId + `)
                                 and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `)
                                 union 
                                 SELECT u.id , up.userId  as visitorId, up.status, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl as image, o.name as occupation
                                 , upd.birthDate, upd.eyeColor, upd.languages, upd.expectation, upd.aboutMe, upd.weight, upd.profileForId , pf.name as profileForName, 
                                 addr.cityName, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upd.birthDate)), '%Y') + 0 AS age,
                                 up.proposalUserId IN (select userBlockId from userblock where userId = ` + userId + `)  as isBlockByMe , 
                                up.proposalUserId IN (select userId from userblock where userBlockId = ` + userId + `)  as isBlockByOther,
                                u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
                                u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
                                 FROM userproposals up 
                                 LEFT JOIN users u ON u.id = up.userId
                                 LEFT JOIN images img ON img.id = u.imageId
                                 LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                                 LEFT JOIN profilefor pf ON pf.id = upd.profileForId
                                 LEFT JOIN occupation o ON o.id = upd.occupationId
                                 LEFT JOIN addresses addr ON addr.id = upd.addressId WHERE up.proposalUserId = ` + userId + ` 
                                 and u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `)  
                                 and u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                                 and u.id NOT IN (select blockRequestUserId from userblockrequest where status = true AND userId = ` + userId + `))  
                                 as t1 WHERE t1.status = true`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + " ";
            }
            let result = await header.query(sql);
            if (result) {

                for (let i = 0; i < result.length; i++) {
                    result[i].isVerifiedProfile = false;
                    let isVerified = true
                    let docVerifiedSql = `SELECT * FROM userdocument WHERE userId =` + userId;
                    let docVerifiedResult = await header.query(docVerifiedSql);
                    if (docVerifiedResult && docVerifiedResult.length > 0) {
                        for (let j = 0; j < docVerifiedResult.length; j++) {
                            if (docVerifiedResult[j].isRequired && !docVerifiedResult[j].isVerified) {
                                isVerified = false;
                            }
                        }
                    } else {
                        isVerified = false;
                    }
                    result[i].isVerifiedProfile = isVerified;
                }

                let successResult = new ResultSuccess(200, true, 'Get Visitors', result, countResult[0].totalCount, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "visitors.getVisitors() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'visitors.getVisitors() Exception', error, '');
        next(errorResult);
    }
};

export default { getVisitors };