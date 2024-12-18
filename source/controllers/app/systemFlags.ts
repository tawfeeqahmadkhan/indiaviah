import { NextFunction, Request, Response, query } from 'express';
import logging from "../../config/logging";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

const NAMESPACE = 'System Flags';
// interface UserProfile {
//     name: string;
//     age?: number;
//     email?: string;
//     }
// const userProfile: UserProfile = {
//     name: "John Doe",
// };
// const propertyName: keyof UserProfile = "age";
// const propertyValue = userProfile[propertyName];

const getSystemFlagForApp = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting SystemFlags');
        let sql = `SELECT * FROM systemflags WHERE isActive = 1`;
        let result = await header.query(sql);
        let reponseData: any = [];
        let obj: any = {}
        if (result && result.length > 0) {
            for (let i = 0; i < result.length; i++) {
                let key = result[i].name;
                let value = result[i].value;
                obj[key] = value;
                // let obj = {
                //     [key]: value
                // }
                // const propertyName: keyof any = key;
                // const propertyValue = userProfile[propertyName];

                //reponseData.push(obj);
            }
        }
        if (result && result.length > 0) {
            let successResult = new ResultSuccess(200, true, 'Get System flag successfully', obj, reponseData.length, '');
            return res.status(200).send(successResult);
        } else {
            let errorResult = new ResultError(400, true, "systemflags.getAdminSystemFlag() Error", new Error('Error While Updating Data'), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'systemflags.getAdminSystemFlag() Exception', error, '');
        next(errorResult);
    }
};

export default { getSystemFlagForApp }