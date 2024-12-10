package org.brsm_system_server.controller;

import org.brsm_system_server.dto.PetitionDTO;
import org.brsm_system_server.entity.Petition;
import org.brsm_system_server.mapper.PetitionMapper;
import org.brsm_system_server.service.interfaces.IPetitionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/petitions")
public class PetitionController {

    @Autowired
    private IPetitionService petitionService;

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/get-all")
    public List<PetitionDTO> getPetitions(){
        List<Petition> petitions = petitionService.getAllPetitions();
        return petitions.stream().map(PetitionMapper::toDto).toList();
    }

}
