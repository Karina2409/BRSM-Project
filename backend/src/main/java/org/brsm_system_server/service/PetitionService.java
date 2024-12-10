package org.brsm_system_server.service;

import org.brsm_system_server.entity.Petition;
import org.brsm_system_server.repository.PetitionRepository;
import org.brsm_system_server.service.interfaces.IPetitionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PetitionService implements IPetitionService {

    @Autowired
    private PetitionRepository petitionRepository;

    @Override
    public List<Petition> getAllPetitions() {
        return petitionRepository.findAll();
    }

}
