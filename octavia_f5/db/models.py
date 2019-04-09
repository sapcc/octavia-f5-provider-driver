# Copyright (c) 2019 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sqlalchemy as sa

from sqlalchemy import orm
from octavia_f5.common import data_models
from octavia.db import base_models


class ESDAttributes(base_models.BASE, base_models.NameMixin):

    __data_model__ = data_models.ESDAttributes

    __tablename__ = "f5_esd_attributes"
    esd_id = sa.Column(
        sa.String(36),
        sa.ForeignKey("f5_esd.id",
                      name="fk_f5_esd_attributes_f5_esd_id"),
        nullable=False)
    type = sa.Column(sa.String(255), nullable=False)


class ESD(base_models.BASE, base_models.IdMixin,
          base_models.NameMixin):

    __data_model__ = data_models.ESD

    __tablename__ = "f5_esd"

    attributes = orm.relationship(
        'ESDAttributes', cascade='delete', uselist=True)