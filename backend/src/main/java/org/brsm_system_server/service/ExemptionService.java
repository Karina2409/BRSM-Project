package org.brsm_system_server.service;

import org.brsm_system_server.entity.Exemption;
import org.brsm_system_server.repository.ExemptionRepository;
import org.brsm_system_server.repository.ExemptionStudentsRepository;
import org.brsm_system_server.service.interfaces.IExemptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ExemptionService implements IExemptionService {

    @Autowired
    private ExemptionRepository exemptionRepository;

    @Autowired
    private ExemptionStudentsRepository exemptionStudentsRepository;

    @Override
    public List<Exemption> getAllExemptions() {
        return exemptionRepository.findAll();
    }

    @Override
    public ResponseEntity<Void> deleteExemptionById(Long exemptionId) {
        Optional<Exemption> exemption = exemptionRepository.findById(exemptionId);
        exemptionStudentsRepository.delete(exemptionStudentsRepository.findById(exemptionId).get());
        if (exemption.isPresent()) {
            exemptionRepository.delete(exemption.get());
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
