# python-cybox
from cybox.objects.file_object import File

# python-stix
from stix import utils as utils
from stix.core import STIXPackage, STIXHeader
from stix.threat_actor import ThreatActor
from stix.indicator import Indicator

def main():

    # Creamos el indicador con la información de la que disponemos
    threatActor = ThreatActor()
    threatActor.title = "Ip/Domain/Hostname"
    threatActor.description = (
        "A threatActor commited with malicious tasks"
    )
    threatActor.information_source = ("Malshare")
    threatActor.timestamp = ("01/05/2019")
    threatActor.identity = ("106.113.123.197")
    threatActor.types = ("eCrime Actor - Spam Service")

    # Creamos el indicador con la información de la que disponemos
    indicator = Indicator()
    indicator.title = "Risk Score"
    indicator.description = (
        "An indicator containing the appropriate Risk Score"
    )
    indicator.set_produced_time("01/05/2019")
    indicator.likely_impact = ("Risk Score: 2(Medium)")
    # Creamos el reporte en STIX, con una brve descripción
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.description = "Feeds in STIX format with their Risk Scores"
    stix_package.stix_header = stix_header

    # Añadimos al reporte el indicador que hemos construido antes
    stix_package.add(threatActor)
    stix_package.add(indicator)
    # Imprimimos el xml en pantalla
    print(stix_package.to_xml())


if __name__ == '__main__':
    main()