import express from 'express';
import controller from '../../controllers/app/region'

const router = express.Router();

router.post('/getCountries', controller.getCountries);
router.post('/getStates', controller.getStates);
router.post('/getDistricts', controller.getDistricts);
router.post('/getCities', controller.getCities);
router.post('/getRegionByPincode', controller.getRegionByPincode);
router.post('/getRegionByPincodeAndCountryISO', controller.getRegionByPincodeAndCountryISO);

export = router;