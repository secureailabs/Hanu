import React from 'react';

import { TUnifiedRegistryError } from './UnifiedRegistry.types';

const UnifiedRegistryFailure: React.FC<TUnifiedRegistryError> = ({ error }) => {
  if(error){
    return <></>;
  }
  return <>An unkown error has occured</>;
};

export default UnifiedRegistryFailure;
