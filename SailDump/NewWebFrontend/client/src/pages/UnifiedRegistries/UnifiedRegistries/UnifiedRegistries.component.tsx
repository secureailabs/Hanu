import React, { useEffect, useState } from 'react';

import { TUnifiedRegistriesProps } from './UnifiedRegistries.types';

import UnifiedRegistriesSuccess from './UnifiedRegistries.success';
import UnifiedRegistriesFailure from './UnifiedRegistries.failure';
import Spinner from '@components/Spinner/SpinnerOnly.component';

import StandardContent from '@secureailabs/web-ui/components/StandardContent';

import { demo_data } from "@APIs/unifiedRegistry/unifiedRegistry.data";

import { useQuery } from 'react-query';
import { TGetAllUnifiedRegistriesSuccess } from '@APIs/unifiedRegistry/unifiedRegistry.types';
import { AxiosError } from 'axios';


const UnifiedRegistries: React.FC<TUnifiedRegistriesProps> = () => {

  // const fetch = (): TGetAllUnifiedRegistriesSuccess['UnifiedRegistries'] => {
  //   return demo_data.UnifiedRegistries;
  //   // const res = await axios.get<TGetAllUnifiedRegistriesSuccess>
  //   // (`${axiosProxy()}/api/v1/DatasetManager/PullDataset?DatasetGuid=${id}`, 
  //   // {
  //   //   withCredentials: true,
  //   // });
  //   // return res.data.UnifiedRegistry;
  // }

  // eslint-disable-next-line max-len
  // @ts-ignore
  const { data, status, isLoading, error } = useQuery<TGetAllUnifiedRegistriesSuccess, AxiosError>(["organizations"], () => demo_data);

  if (isLoading) {
    return <><Spinner /></>
  }
  if (status === 'success' && data) {
    return (
      <StandardContent title="Unified Registries">
        <UnifiedRegistriesSuccess
          // @ts-ignore
          getAllUnifiedRegistriesData={data}
        />
      </StandardContent>
    )
  }
  return <UnifiedRegistriesFailure error={error} />
};

export default UnifiedRegistries;
