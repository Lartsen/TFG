
# python-cybox
from cybox.objects.file_object import File

# python-stix
from stix import utils as utils
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.indicator import Indicator

def main():
    # Crea un objeto vía CybOX
    f = File()

    # Asocia el hash a dicho objeto, la tipología del hash la detecta automáticamente en función de su amplitud
    f.add_hash("8994a4713713e4683117e35d8689ea24")

    # Creamos el indicador con la información de la que disponemos
    indicator = Indicator()
    indicator.title = "Feeds and Risk Score"
    indicator.description = (
        "An indicator containing the feed and the appropriate Risk Score"
    )
    indicator.set_producer_identity("Malshare")
    indicator.set_produced_time("01/05/2019")
    indicator.likely_impact = ("Risk Score: 4(Critical)")

    # Asociamos el hash anterior a nuestro indicador
    indicator.add_object(f)

    # Creamos el reporte en STIX, con una brve descripción
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.description = "Feeds in STIX format with their Risk Scores"
    stix_package.stix_header = stix_header

    # Añadimos al reporte el indicador que hemos construido antes
    stix_package.add(indicator)

    # Imprimimos el xml en pantalla
    print(stix_package.to_xml())


if __name__ == '__main__':
    main()