package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Exemption;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface IExemptionService {
    List<Exemption> getAllExemptions();
    ResponseEntity<Void> deleteExemptionById(Long exemptionId);
    ResponseEntity<Void> downloadExemption(Long exemptionId);
}
