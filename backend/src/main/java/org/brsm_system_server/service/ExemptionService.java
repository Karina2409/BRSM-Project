package org.brsm_system_server.service;

import org.brsm_system_server.entity.Exemption;
import org.brsm_system_server.repository.ExemptionRepository;
import org.brsm_system_server.service.interfaces.IExemptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ExemptionService implements IExemptionService {

    @Autowired
    private ExemptionRepository exemptionRepository;

    @Override
    public List<Exemption> getAllExemptions() {
        return exemptionRepository.findAll();
    }
}
