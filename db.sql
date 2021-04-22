--DROP DATABASE odr;
create user odru with password 'odrpass';
create database odr with ENCODING='UTF8' OWNER=odru;
alter database "odr" set DateStyle =iso, dmy;

grant all privileges on database odr to odru;

\c odr;

--open dns resolver main tables
create table opendnsv4(
    id serial not null constraint opdv4_pk primary key,
    bloc varchar not null,
    cidr integer not null,
    zmap varchar not null,
    openresolver boolean not null,
    datetest date not null
);
alter table opendnsv4 owner to odru;


create table ipv4T(
    id serial not null constraint ipv4t_pkey primary key,
    ipStart varchar not null,
    cidr integer not null,
    cc varchar not null,
    blocStatus varchar not null,
    numAsn varchar not null,
    orgName varchar not null,
    descOrg varchar not null,
    dateSave date not null
);

alter table ipv4T owner to odru;


create table summaryTest(
    id serial not null constraint sumt_pkey primary key,
    startDate date not null,
    endDate date not null,
    testDuration time not null,
    numBlocIPV4 integer not null,
    numODRIPV4 integer not null
);

alter table summaryTest owner to odru;