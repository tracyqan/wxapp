# -*- coding: utf-8 -*-
import scrapy
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from wxapp.items import WxappItem


class WxspiderSpider(CrawlSpider):
    name = 'wxspider'
    allowed_domains = ['wxapp-union.com']
    start_urls = ['http://www.wxapp-union.com/portal.php?mod=list&catid=1&page=1']

    rules = (
        Rule(LinkExtractor(allow=r'.+?mod=list&catid=1&page=\d{1,3}'), follow=True),
        Rule(LinkExtractor(allow=r'.+/article-.+\.html'), callback='parse_detail')
    )

    def parse_detail(self, response):
        items = WxappItem()
        items['title'] = response.xpath('//h1[@class="ph"]/text()').get()
        items['author'] = response.xpath('//p[@class="authors"]/a/text()').get()
        items['pubtime'] = response.xpath('//span[@class="time"]/text()').get()
        items['focus_num'] = response.xpath('//div[@class="focus_num cl"]/a/text()').get()
        contents = response.xpath('////td[@id="article_content"]//p//text()').getall()
        items['content'] = ''.join(contents).strip()
        yield items


if __name__ == '__main__':
    from scrapy import cmdline
    cmdline.execute('scrapy crawl {}'.format(WxspiderSpider.name).split())