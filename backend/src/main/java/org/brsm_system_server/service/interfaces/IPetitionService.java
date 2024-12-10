package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Petition;

import java.util.List;

public interface IPetitionService {
    List<Petition> getAllPetitions();
}
