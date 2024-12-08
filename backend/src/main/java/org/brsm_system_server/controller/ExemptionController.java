package org.brsm_system_server.controller;

import org.brsm_system_server.dto.ExemptionDTO;
import org.brsm_system_server.entity.Exemption;
import org.brsm_system_server.mapper.ExemptionMapper;
import org.brsm_system_server.service.interfaces.IExemptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/exemptions")
public class ExemptionController {

    @Autowired
    private IExemptionService exemptionService;

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/get-all")
    public List<ExemptionDTO> getExemptions() {
        List<Exemption> exemptions = exemptionService.getAllExemptions();
        return exemptions.stream().map(ExemptionMapper::toDto).toList();
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @DeleteMapping("/delete/{exemptionId}")
    public ResponseEntity<Void> deleteExemption(@PathVariable Long exemptionId) {
        return exemptionService.deleteExemptionById(exemptionId);
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/download/{exemptionId}")
    public ResponseEntity<Void> downloadExemption(@PathVariable Long exemptionId) {
        return exemptionService.downloadExemption(exemptionId);
    }
}
