import express from 'express';
import controller from '../../controllers/admin/region';

const router = express.Router();

router.post('/getCountries', controller.getCountries);
router.post('/insertCountry', controller.insertCountry);
router.post('/updateCountry', controller.updateCountry);
router.post('/activeInactiveCountry', controller.activeInactiveCountry);
router.post('/getStates', controller.getStates);
router.post('/insertState', controller.insertState);
router.post('/updateState', controller.updateState);
router.post('/activeInactiveState', controller.activeInactiveState);
router.post('/getDistricts', controller.getDistricts);
router.post('/insertDistrict', controller.insertDistrict);
router.post('/updateDistrict', controller.updateDistrict);
router.post('/activeInactiveDistrict', controller.activeInactiveDistrict);
router.post('/getCities', controller.getCities);
router.post('/insertCity', controller.insertCity);
router.post('/updateCity', controller.updateCity);
router.post('/activeInactiveCity', controller.activeInactiveCity);
router.post('/getAllRegionData', controller.getAllRegionData);
router.post('/updateRegionData', controller.updateRegionData);

export = router;